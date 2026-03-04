#!/usr/bin/env python3
"""Decode RPG data.pak (PAKX -> PAK1data -> zlib -> AES-CBC JSON)."""

from __future__ import annotations

import argparse
import json
import struct
import zlib
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any


PAKX_MAGIC = b"PAKX"
PAK1_MAGIC = b"PAK1data"
PAK1_HEADER_SIZE = 44
DEFAULT_KEY_TEXT = "2cde28fa56162f4738f27809abd51ef4"


class PakFormatError(ValueError):
    pass


@dataclass
class Pak1Entry:
    path: str
    original_size: int
    compressed_size: int
    offset_in_package: int
    record_size: int


def _u32_le(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise PakFormatError("Unexpected end while reading u32")
    return struct.unpack_from("<I", data, offset)[0]


def decode_index_data(index_blob: bytes) -> bytes:
    return bytes((b ^ ((90 + (i % 32)) & 0xFF)) for i, b in enumerate(index_blob))


def parse_pakx(data: bytes) -> tuple[dict[str, Any], bytes, int]:
    if len(data) < 8:
        raise PakFormatError("File too short for PAKX header")
    if data[:4] != PAKX_MAGIC:
        raise PakFormatError("Not a PAKX data.pak file")

    index_len = _u32_le(data, 4)
    index_start = 8
    index_end = index_start + index_len
    if index_end > len(data):
        raise PakFormatError("Index length exceeds file size")

    index_json_bytes = decode_index_data(data[index_start:index_end])
    try:
        index = json.loads(index_json_bytes.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise PakFormatError("Decoded index is not valid JSON") from exc

    package_base = index_end
    package_data = data[package_base:]
    return index, package_data, package_base


def parse_package_entries(package_data: bytes) -> list[Pak1Entry]:
    entries: list[Pak1Entry] = []
    cursor = 0
    total = len(package_data)

    while cursor < total:
        if cursor + PAK1_HEADER_SIZE > total:
            raise PakFormatError(f"Truncated record header at package offset {cursor}")

        if package_data[cursor : cursor + 8] != PAK1_MAGIC:
            raise PakFormatError(f"PAK1data magic mismatch at package offset {cursor}")

        original_size = _u32_le(package_data, cursor + 12)
        compressed_size = _u32_le(package_data, cursor + 16)
        name_len = _u32_le(package_data, cursor + 20)

        name_start = cursor + PAK1_HEADER_SIZE
        name_end = name_start + name_len
        if name_end > total:
            raise PakFormatError(f"Name overruns package at offset {cursor}")

        try:
            path = package_data[name_start:name_end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PakFormatError(f"Entry name is not utf-8 at offset {cursor}") from exc

        payload_start = name_end
        payload_end = payload_start + compressed_size
        if payload_end > total:
            raise PakFormatError(
                f"Compressed payload overruns package at offset {cursor}"
            )

        record_size = PAK1_HEADER_SIZE + name_len + compressed_size
        entries.append(
            Pak1Entry(
                path=path,
                original_size=original_size,
                compressed_size=compressed_size,
                offset_in_package=cursor,
                record_size=record_size,
            )
        )
        cursor = payload_end

    return entries


def _decrypt_aes_cbc(ciphertext: bytes, key_text: str, iv_hex: str) -> bytes:
    try:
        aes_module = import_module("Crypto.Cipher.AES")
        padding_module = import_module("Crypto.Util.Padding")
    except ImportError as exc:
        raise RuntimeError(
            "pycryptodome is required. Install with: python -m pip install pycryptodome"
        ) from exc

    unpad = getattr(padding_module, "unpad")

    key = key_text.encode("utf-8")
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be 32 bytes, got {len(key)}")

    iv = bytes.fromhex(iv_hex)
    cipher = aes_module.new(key, aes_module.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ciphertext)
    try:
        return unpad(padded, aes_module.block_size, style="pkcs7")
    except ValueError as exc:
        raise RuntimeError("AES decrypt succeeded but PKCS7 unpad failed") from exc


def decode_entry_json(
    package_data: bytes, entry: Pak1Entry, key_text: str
) -> tuple[Any, dict[str, Any]]:
    name_start = entry.offset_in_package + PAK1_HEADER_SIZE
    payload_start = name_start + len(entry.path.encode("utf-8"))
    payload_end = payload_start + entry.compressed_size

    compressed = package_data[payload_start:payload_end]
    wrapper_raw = zlib.decompress(compressed)
    wrapper_obj = json.loads(wrapper_raw.decode("utf-8"))

    iv = wrapper_obj.get("iv")
    encrypted_hex = wrapper_obj.get("encryptedData")
    if not isinstance(iv, str) or not isinstance(encrypted_hex, str):
        raise PakFormatError(f"Entry {entry.path} wrapper missing iv/encryptedData")

    encrypted = bytes.fromhex(encrypted_hex)
    plain = _decrypt_aes_cbc(encrypted, key_text=key_text, iv_hex=iv)
    data_obj = json.loads(plain.decode("utf-8"))
    return data_obj, wrapper_obj


def command_info(file_path: Path) -> None:
    data = file_path.read_bytes()
    index, package_data, package_base = parse_pakx(data)
    entries = parse_package_entries(package_data)

    print(f"file={file_path}")
    print(f"file_size={len(data)}")
    print(f"package_base={package_base}")
    print(f"index_version={index.get('version')}")
    print(f"index_file_count={index.get('fileCount')}")
    print(f"parsed_entries={len(entries)}")
    if entries:
        print(f"first_entry={entries[0].path}")
        print(f"last_entry={entries[-1].path}")


def command_list(file_path: Path, output_json: Path | None) -> None:
    data = file_path.read_bytes()
    index, package_data, package_base = parse_pakx(data)
    entries = parse_package_entries(package_data)

    rows: list[dict[str, Any]] = []
    index_files = index.get("files", [])
    index_map = {
        f.get("path"): f
        for f in index_files
        if isinstance(f, dict) and isinstance(f.get("path"), str)
    }

    for ent in entries:
        idx = index_map.get(ent.path, {})
        rows.append(
            {
                "path": ent.path,
                "packageOffset": ent.offset_in_package,
                "packageOffsetAbsolute": package_base + ent.offset_in_package,
                "originalSize": ent.original_size,
                "compressedSize": ent.compressed_size,
                "recordSize": ent.record_size,
                "indexOffset": idx.get("offset"),
                "indexCompressedSize": idx.get("compressedSize"),
                "indexOriginalSize": idx.get("originalSize"),
            }
        )

    if output_json is None:
        output_json = file_path.with_suffix(".entries.json")
    output_json.write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"entries_json={output_json}")
    print(f"entries={len(rows)}")


def command_batch_decode(
    file_path: Path, output_dir: Path, key_text: str, overwrite: bool
) -> None:
    data = file_path.read_bytes()
    _, package_data, _ = parse_pakx(data)
    entries = parse_package_entries(package_data)
    output_dir.mkdir(parents=True, exist_ok=True)

    ok_count = 0
    skip_count = 0
    err_count = 0
    report: list[dict[str, Any]] = []

    for ent in entries:
        out_file = output_dir / ent.path
        if out_file.exists() and not overwrite:
            skip_count += 1
            report.append(
                {"path": ent.path, "status": "skipped", "output": str(out_file)}
            )
            continue

        out_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            decoded, wrapper = decode_entry_json(package_data, ent, key_text=key_text)
            out_file.write_text(
                json.dumps(decoded, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            ok_count += 1
            report.append(
                {
                    "path": ent.path,
                    "status": "ok",
                    "output": str(out_file),
                    "iv": wrapper.get("iv"),
                    "originalSize": ent.original_size,
                    "compressedSize": ent.compressed_size,
                }
            )
        except Exception as exc:  # noqa: BLE001
            err_count += 1
            report.append(
                {"path": ent.path, "status": "decode_error", "error": str(exc)}
            )

    report_path = output_dir / "_batch_report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"file={file_path}")
    print(f"output_dir={output_dir}")
    print(f"entries={len(entries)}")
    print(f"ok={ok_count}")
    print(f"skipped={skip_count}")
    print(f"decode_error={err_count}")
    print(f"report={report_path}")


def _safe_load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_rows(arr: Any, kind: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not isinstance(arr, list):
        return rows
    for obj in arr:
        if not isinstance(obj, dict):
            continue
        id_val = obj.get("id")
        if not isinstance(id_val, int):
            continue
        rows.append(
            {
                "id": id_val,
                "kind": kind,
                "name": obj.get("name", ""),
                "iconIndex": obj.get("iconIndex"),
                "price": obj.get("price"),
                "description": obj.get("description", ""),
                "itypeId": obj.get("itypeId"),
                "wtypeId": obj.get("wtypeId"),
                "atypeId": obj.get("atypeId"),
                "etypeId": obj.get("etypeId"),
                "stypeId": obj.get("stypeId"),
                "mpCost": obj.get("mpCost"),
                "tpCost": obj.get("tpCost"),
            }
        )
    return rows


def command_build_id_map(data_dir: Path, output_json: Path) -> None:
    files = {
        "items": data_dir / "Items.json",
        "weapons": data_dir / "Weapons.json",
        "armors": data_dir / "Armors.json",
        "skills": data_dir / "Skills.json",
    }
    for key, path in files.items():
        if not path.exists():
            raise FileNotFoundError(f"Missing decoded file for {key}: {path}")

    items = _extract_rows(_safe_load_json(files["items"]), "item")
    weapons = _extract_rows(_safe_load_json(files["weapons"]), "weapon")
    armors = _extract_rows(_safe_load_json(files["armors"]), "armor")
    skills = _extract_rows(_safe_load_json(files["skills"]), "skill")

    payload = {
        "sourceDir": str(data_dir),
        "counts": {
            "items": len(items),
            "weapons": len(weapons),
            "armors": len(armors),
            "skills": len(skills),
        },
        "items": items,
        "weapons": weapons,
        "armors": armors,
        "skills": skills,
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"id_map={output_json}")
    print(f"items={len(items)}")
    print(f"weapons={len(weapons)}")
    print(f"armors={len(armors)}")
    print(f"skills={len(skills)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decode data.pak into decrypted JSON data files"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="show package/index summary")
    p_info.add_argument("file", type=Path)

    p_list = sub.add_parser("list", help="export entry metadata list")
    p_list.add_argument("file", type=Path)
    p_list.add_argument("output", nargs="?", type=Path)

    p_batch = sub.add_parser(
        "batch-decode", help="decode all entries to output directory"
    )
    p_batch.add_argument("file", type=Path)
    p_batch.add_argument("output_dir", type=Path)
    p_batch.add_argument(
        "--key", default=DEFAULT_KEY_TEXT, help="AES key text (not hex)"
    )
    p_batch.add_argument(
        "--overwrite", action="store_true", help="overwrite existing output files"
    )

    p_id_map = sub.add_parser(
        "build-id-map", help="build merged id map from decoded JSON"
    )
    p_id_map.add_argument("data_dir", type=Path)
    p_id_map.add_argument("output", type=Path)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "info":
        command_info(args.file)
        return
    if args.cmd == "list":
        command_list(args.file, args.output)
        return
    if args.cmd == "batch-decode":
        command_batch_decode(
            args.file, args.output_dir, key_text=args.key, overwrite=args.overwrite
        )
        return
    if args.cmd == "build-id-map":
        command_build_id_map(args.data_dir, args.output)
        return

    parser.error("Unknown command")


if __name__ == "__main__":
    main()
