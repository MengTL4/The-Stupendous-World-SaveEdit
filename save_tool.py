#!/usr/bin/env python3
"""RPG Maker save encrypt/decrypt tool (Base64 -> zlib -> MessagePack)."""

from __future__ import annotations

import argparse
import base64
import json
import re
import struct
import zlib
from pathlib import Path
from typing import Any


BASE64_PAYLOAD_RE = re.compile(r"[A-Za-z0-9+/=\r\n]{32,}")


class MsgPackError(ValueError):
    pass


class MsgPackDecoder:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def _ensure(self, size: int) -> None:
        if self.offset + size > len(self.data):
            raise MsgPackError("Unexpected end of MessagePack data")

    def _read_u8(self) -> int:
        self._ensure(1)
        value = self.data[self.offset]
        self.offset += 1
        return value

    def _read_i8(self) -> int:
        self._ensure(1)
        value = struct.unpack_from(">b", self.data, self.offset)[0]
        self.offset += 1
        return value

    def _read_u16(self) -> int:
        self._ensure(2)
        value = struct.unpack_from(">H", self.data, self.offset)[0]
        self.offset += 2
        return value

    def _read_i16(self) -> int:
        self._ensure(2)
        value = struct.unpack_from(">h", self.data, self.offset)[0]
        self.offset += 2
        return value

    def _read_u32(self) -> int:
        self._ensure(4)
        value = struct.unpack_from(">I", self.data, self.offset)[0]
        self.offset += 4
        return value

    def _read_i32(self) -> int:
        self._ensure(4)
        value = struct.unpack_from(">i", self.data, self.offset)[0]
        self.offset += 4
        return value

    def _read_u64(self) -> int:
        self._ensure(8)
        value = struct.unpack_from(">Q", self.data, self.offset)[0]
        self.offset += 8
        return value

    def _read_i64(self) -> int:
        self._ensure(8)
        value = struct.unpack_from(">q", self.data, self.offset)[0]
        self.offset += 8
        return value

    def _read_f32(self) -> float:
        self._ensure(4)
        value = struct.unpack_from(">f", self.data, self.offset)[0]
        self.offset += 4
        return value

    def _read_f64(self) -> float:
        self._ensure(8)
        value = struct.unpack_from(">d", self.data, self.offset)[0]
        self.offset += 8
        return value

    def _read_bytes(self, size: int) -> bytes:
        self._ensure(size)
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def _read_str(self, size: int) -> str:
        return self._read_bytes(size).decode("utf-8")

    def decode(self) -> Any:
        marker = self._read_u8()

        if marker <= 0x7F:
            return marker
        if marker >= 0xE0:
            return marker - 0x100

        if 0xA0 <= marker <= 0xBF:
            return self._read_str(marker & 0x1F)
        if 0x90 <= marker <= 0x9F:
            return self._decode_array(marker & 0x0F)
        if 0x80 <= marker <= 0x8F:
            return self._decode_map(marker & 0x0F)

        if marker == 0xC0:
            return None
        if marker == 0xC2:
            return False
        if marker == 0xC3:
            return True
        if marker == 0xC4:
            return self._read_bytes(self._read_u8())
        if marker == 0xC5:
            return self._read_bytes(self._read_u16())
        if marker == 0xC6:
            return self._read_bytes(self._read_u32())
        if marker == 0xC7:
            return self._decode_ext(self._read_u8())
        if marker == 0xC8:
            return self._decode_ext(self._read_u16())
        if marker == 0xC9:
            return self._decode_ext(self._read_u32())
        if marker == 0xCA:
            return self._read_f32()
        if marker == 0xCB:
            return self._read_f64()
        if marker == 0xCC:
            return self._read_u8()
        if marker == 0xCD:
            return self._read_u16()
        if marker == 0xCE:
            return self._read_u32()
        if marker == 0xCF:
            return self._read_u64()
        if marker == 0xD0:
            return self._read_i8()
        if marker == 0xD1:
            return self._read_i16()
        if marker == 0xD2:
            return self._read_i32()
        if marker == 0xD3:
            return self._read_i64()
        if marker == 0xD4:
            return self._decode_fixext(1)
        if marker == 0xD5:
            return self._decode_fixext(2)
        if marker == 0xD6:
            return self._decode_fixext(4)
        if marker == 0xD7:
            return self._decode_fixext(8)
        if marker == 0xD8:
            return self._decode_fixext(16)
        if marker == 0xD9:
            return self._read_str(self._read_u8())
        if marker == 0xDA:
            return self._read_str(self._read_u16())
        if marker == 0xDB:
            return self._read_str(self._read_u32())
        if marker == 0xDC:
            return self._decode_array(self._read_u16())
        if marker == 0xDD:
            return self._decode_array(self._read_u32())
        if marker == 0xDE:
            return self._decode_map(self._read_u16())
        if marker == 0xDF:
            return self._decode_map(self._read_u32())

        raise MsgPackError(f"Unsupported MessagePack marker: 0x{marker:02x}")

    def _decode_array(self, length: int) -> list[Any]:
        return [self.decode() for _ in range(length)]

    def _decode_map(self, length: int) -> Any:
        pairs: list[list[Any]] = []
        obj: dict[str, Any] = {}
        can_use_object = True

        for _ in range(length):
            key = self.decode()
            value = self.decode()
            pairs.append([key, value])

            if not isinstance(key, str) or key in obj:
                can_use_object = False
            else:
                obj[key] = value

        if can_use_object:
            return obj
        return {"$map": pairs}

    def _decode_ext(self, size: int) -> dict[str, Any]:
        ext_type = self._read_i8()
        data = self._read_bytes(size)
        return {"$ext": {"type": ext_type, "data": data}}

    def _decode_fixext(self, size: int) -> dict[str, Any]:
        ext_type = self._read_i8()
        data = self._read_bytes(size)
        return {"$ext": {"type": ext_type, "data": data}}


class MsgPackEncoder:
    def __init__(self) -> None:
        self.parts: list[bytes] = []

    def _write(self, value: bytes) -> None:
        self.parts.append(value)

    def _write_u8(self, value: int) -> None:
        self.parts.append(bytes((value & 0xFF,)))

    def encode(self, value: Any) -> None:
        if value is None:
            self._write_u8(0xC0)
            return
        if value is False:
            self._write_u8(0xC2)
            return
        if value is True:
            self._write_u8(0xC3)
            return

        if isinstance(value, int):
            self._encode_int(value)
            return
        if isinstance(value, float):
            self._write_u8(0xCB)
            self._write(struct.pack(">d", value))
            return
        if isinstance(value, str):
            self._encode_str(value)
            return
        if isinstance(value, (bytes, bytearray, memoryview)):
            self._encode_bin(bytes(value))
            return
        if isinstance(value, list):
            self._encode_array(value)
            return

        if isinstance(value, dict):
            if set(value.keys()) == {"$ext"} and isinstance(value["$ext"], dict):
                self._encode_ext_marker(value)
                return
            if set(value.keys()) == {"$map"} and isinstance(value["$map"], list):
                self._encode_map_pairs(value["$map"])
                return
            self._encode_object(value)
            return

        raise MsgPackError(f"Unsupported value type for MessagePack: {type(value)}")

    def _encode_int(self, value: int) -> None:
        if value >= 0:
            if value <= 0x7F:
                self._write_u8(value)
            elif value <= 0xFF:
                self._write_u8(0xCC)
                self._write_u8(value)
            elif value <= 0xFFFF:
                self._write_u8(0xCD)
                self._write(struct.pack(">H", value))
            elif value <= 0xFFFFFFFF:
                self._write_u8(0xCE)
                self._write(struct.pack(">I", value))
            elif value <= 0xFFFFFFFFFFFFFFFF:
                self._write_u8(0xCF)
                self._write(struct.pack(">Q", value))
            else:
                raise MsgPackError("Integer too large for uint64")
            return

        if value >= -32:
            self._write_u8(value & 0xFF)
        elif value >= -128:
            self._write_u8(0xD0)
            self._write(struct.pack(">b", value))
        elif value >= -32768:
            self._write_u8(0xD1)
            self._write(struct.pack(">h", value))
        elif value >= -2147483648:
            self._write_u8(0xD2)
            self._write(struct.pack(">i", value))
        elif value >= -9223372036854775808:
            self._write_u8(0xD3)
            self._write(struct.pack(">q", value))
        else:
            raise MsgPackError("Integer too small for int64")

    def _encode_str(self, value: str) -> None:
        raw = value.encode("utf-8")
        size = len(raw)
        if size <= 31:
            self._write_u8(0xA0 | size)
        elif size <= 0xFF:
            self._write_u8(0xD9)
            self._write_u8(size)
        elif size <= 0xFFFF:
            self._write_u8(0xDA)
            self._write(struct.pack(">H", size))
        else:
            self._write_u8(0xDB)
            self._write(struct.pack(">I", size))
        self._write(raw)

    def _encode_bin(self, value: bytes) -> None:
        size = len(value)
        if size <= 0xFF:
            self._write_u8(0xC4)
            self._write_u8(size)
        elif size <= 0xFFFF:
            self._write_u8(0xC5)
            self._write(struct.pack(">H", size))
        else:
            self._write_u8(0xC6)
            self._write(struct.pack(">I", size))
        self._write(value)

    def _encode_array(self, value: list[Any]) -> None:
        size = len(value)
        if size <= 15:
            self._write_u8(0x90 | size)
        elif size <= 0xFFFF:
            self._write_u8(0xDC)
            self._write(struct.pack(">H", size))
        else:
            self._write_u8(0xDD)
            self._write(struct.pack(">I", size))

        for item in value:
            self.encode(item)

    def _encode_object(self, value: dict[str, Any]) -> None:
        size = len(value)
        if size <= 15:
            self._write_u8(0x80 | size)
        elif size <= 0xFFFF:
            self._write_u8(0xDE)
            self._write(struct.pack(">H", size))
        else:
            self._write_u8(0xDF)
            self._write(struct.pack(">I", size))

        for key, item in value.items():
            if not isinstance(key, str):
                raise MsgPackError("Only string keys are supported in plain objects")
            self._encode_str(key)
            self.encode(item)

    def _encode_map_pairs(self, pairs: list[Any]) -> None:
        size = len(pairs)
        if size <= 15:
            self._write_u8(0x80 | size)
        elif size <= 0xFFFF:
            self._write_u8(0xDE)
            self._write(struct.pack(">H", size))
        else:
            self._write_u8(0xDF)
            self._write(struct.pack(">I", size))

        for pair in pairs:
            if not isinstance(pair, list) or len(pair) != 2:
                raise MsgPackError("$map entries must be [key, value]")
            self.encode(pair[0])
            self.encode(pair[1])

    def _encode_ext_marker(self, value: dict[str, Any]) -> None:
        ext = value["$ext"]
        ext_type = int(ext.get("type", 0))
        if ext_type < -128 or ext_type > 127:
            raise MsgPackError("Extension type must be in int8 range")

        data = ext.get("data", b"")
        if isinstance(data, str):
            data = base64.b64decode(data)
        elif isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        elif not isinstance(data, bytes):
            raise MsgPackError("$ext.data must be bytes or base64 string")

        size = len(data)
        type_byte = struct.pack(">b", ext_type)

        if size == 1:
            self._write_u8(0xD4)
            self._write(type_byte)
            self._write(data)
            return
        if size == 2:
            self._write_u8(0xD5)
            self._write(type_byte)
            self._write(data)
            return
        if size == 4:
            self._write_u8(0xD6)
            self._write(type_byte)
            self._write(data)
            return
        if size == 8:
            self._write_u8(0xD7)
            self._write(type_byte)
            self._write(data)
            return
        if size == 16:
            self._write_u8(0xD8)
            self._write(type_byte)
            self._write(data)
            return

        if size <= 0xFF:
            self._write_u8(0xC7)
            self._write_u8(size)
        elif size <= 0xFFFF:
            self._write_u8(0xC8)
            self._write(struct.pack(">H", size))
        else:
            self._write_u8(0xC9)
            self._write(struct.pack(">I", size))
        self._write(type_byte)
        self._write(data)

    def finish(self) -> bytes:
        return b"".join(self.parts)


def decode_msgpack(data: bytes) -> Any:
    decoder = MsgPackDecoder(data)
    value = decoder.decode()
    if decoder.offset != len(data):
        raise MsgPackError(f"Trailing MessagePack bytes: {len(data) - decoder.offset}")
    return value


def encode_msgpack(value: Any) -> bytes:
    encoder = MsgPackEncoder()
    encoder.encode(value)
    return encoder.finish()


def extract_base64_payload(text: str) -> str:
    compact = "".join(text.split())
    if compact and all(
        ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        for ch in compact
    ):
        return compact

    matches = BASE64_PAYLOAD_RE.findall(text)
    if not matches:
        raise ValueError("No base64 payload found in save file")

    cleaned = ["".join(match.split()) for match in matches]
    return max(cleaned, key=len)


def decode_save_text(save_text: str) -> Any:
    payload = extract_base64_payload(save_text)
    compressed = base64.b64decode(payload)
    packed = zlib.decompress(compressed)
    return decode_msgpack(packed)


def encode_save_text(value: Any) -> str:
    packed = encode_msgpack(value)
    compressed = zlib.compress(packed, level=9)
    return base64.b64encode(compressed).decode("ascii")


def to_json_friendly(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$binary": base64.b64encode(value).decode("ascii")}

    if isinstance(value, list):
        return [to_json_friendly(item) for item in value]

    if isinstance(value, dict):
        if set(value.keys()) == {"$ext"} and isinstance(value["$ext"], dict):
            ext_type = int(value["$ext"].get("type", 0))
            ext_data = value["$ext"].get("data", b"")
            if isinstance(ext_data, str):
                encoded = ext_data
            else:
                encoded = base64.b64encode(bytes(ext_data)).decode("ascii")
            return {"$ext": {"type": ext_type, "data": encoded}}

        if set(value.keys()) == {"$map"} and isinstance(value["$map"], list):
            out_pairs: list[list[Any]] = []
            for pair in value["$map"]:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise ValueError("$map entries must be [key, value]")
                out_pairs.append([to_json_friendly(pair[0]), to_json_friendly(pair[1])])
            return {"$map": out_pairs}

        return {key: to_json_friendly(item) for key, item in value.items()}

    return value


def from_json_friendly(value: Any) -> Any:
    if isinstance(value, list):
        return [from_json_friendly(item) for item in value]

    if isinstance(value, dict):
        if set(value.keys()) == {"$binary"} and isinstance(value["$binary"], str):
            return base64.b64decode(value["$binary"])

        if set(value.keys()) == {"$ext"} and isinstance(value["$ext"], dict):
            ext_type = int(value["$ext"].get("type", 0))
            ext_data = base64.b64decode(value["$ext"].get("data", ""))
            return {"$ext": {"type": ext_type, "data": ext_data}}

        if set(value.keys()) == {"$map"} and isinstance(value["$map"], list):
            out_pairs: list[list[Any]] = []
            for pair in value["$map"]:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise ValueError("$map entries must be [key, value]")
                out_pairs.append(
                    [from_json_friendly(pair[0]), from_json_friendly(pair[1])]
                )
            return {"$map": out_pairs}

        return {key: from_json_friendly(item) for key, item in value.items()}

    return value


def default_decode_output(input_path: Path) -> Path:
    if input_path.suffix.lower() == ".rpgsave":
        return input_path.with_suffix(".decoded.json")
    return input_path.with_name(input_path.name + ".decoded.json")


def default_encode_output(input_path: Path) -> Path:
    if input_path.suffix.lower() == ".json":
        return input_path.with_suffix(".rebuilt.rpgsave")
    return input_path.with_name(input_path.name + ".rebuilt.rpgsave")


def cmd_decode(input_file: Path, output_file: Path | None) -> None:
    target = output_file or default_decode_output(input_file)
    raw_text = input_file.read_text(encoding="utf-8", errors="ignore")
    obj = decode_save_text(raw_text)
    target.write_text(
        json.dumps(to_json_friendly(obj), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Decoded: {input_file}")
    print(f"Wrote JSON: {target}")


def cmd_encode(input_file: Path, output_file: Path | None) -> None:
    target = output_file or default_encode_output(input_file)
    obj = from_json_friendly(json.loads(input_file.read_text(encoding="utf-8")))
    save_text = encode_save_text(obj)
    target.write_text(save_text, encoding="utf-8")
    print(f"Encoded JSON: {input_file}")
    print(f"Wrote save: {target}")


def cmd_inspect(input_file: Path) -> None:
    raw_text = input_file.read_text(encoding="utf-8", errors="ignore")
    obj = decode_save_text(raw_text)
    print(f"File: {input_file}")
    print(f"Size: {input_file.stat().st_size} bytes")
    if isinstance(obj, dict):
        keys = list(obj.keys())
        print("Top-level type: object")
        print(f"Top-level keys ({len(keys)}): {', '.join(keys[:50])}")
        party = obj.get("party") or obj.get("$gameParty")
        if isinstance(party, dict) and isinstance(party.get("_gold"), int):
            print(f"Party gold: {party['_gold']}")
    elif isinstance(obj, list):
        print("Top-level type: array")
        print(f"Top-level length: {len(obj)}")
    else:
        print(f"Top-level type: {type(obj).__name__}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RPG Maker save encrypt/decrypt tool (base64 + zlib + MessagePack)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_decode = sub.add_parser("decode", help="Decode .rpgsave to JSON")
    p_decode.add_argument("input", type=Path, help="Input .rpgsave")
    p_decode.add_argument("output", type=Path, nargs="?", help="Output JSON path")

    p_encode = sub.add_parser("encode", help="Encode JSON back to .rpgsave")
    p_encode.add_argument("input", type=Path, help="Input JSON")
    p_encode.add_argument("output", type=Path, nargs="?", help="Output .rpgsave path")

    p_inspect = sub.add_parser("inspect", help="Inspect key metadata in a save")
    p_inspect.add_argument("input", type=Path, help="Input .rpgsave")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "decode":
        cmd_decode(args.input, args.output)
        return
    if args.command == "encode":
        cmd_encode(args.input, args.output)
        return
    if args.command == "inspect":
        cmd_inspect(args.input)
        return

    parser.error("Unknown command")


if __name__ == "__main__":
    main()
