#!/usr/bin/env python3
"""Decode useData/*.data blobs (gzip + MessagePack with possible header offset)."""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from importlib import import_module
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
st = import_module("save_tool")


def decode_best(raw: bytes, max_offset: int = 40) -> tuple[int, Any, int]:
    best: tuple[int, Any, int] | None = None
    for off in range(0, max_offset + 1):
        try:
            decoder = st.MsgPackDecoder(raw[off:])
            value = decoder.decode()
            consumed = decoder.offset
            if best is None or consumed > best[2]:
                best = (off, value, consumed)
        except Exception:
            continue
    if best is None:
        raise ValueError("No decodable MessagePack payload found in first offsets")
    return best


def command_info(file_path: Path) -> None:
    raw = gzip.decompress(file_path.read_bytes())
    off, value, consumed = decode_best(raw)
    top_type = type(value).__name__
    print(f"file={file_path}")
    print(f"gzip_raw_len={len(raw)}")
    print(f"best_offset={off}")
    print(f"msgpack_consumed={consumed}")
    print(f"trailing_bytes={len(raw) - off - consumed}")
    print(f"top_type={top_type}")
    if isinstance(value, dict):
        print(f"top_keys={list(value.keys())[:30]}")


def command_decode(file_path: Path, output_json: Path | None) -> None:
    raw = gzip.decompress(file_path.read_bytes())
    off, value, consumed = decode_best(raw)
    if output_json is None:
        output_json = file_path.with_suffix(".decoded.json")

    friendly = st.to_json_friendly(value)
    output_json.write_text(
        json.dumps(friendly, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"decoded_file={output_json}")
    print(f"best_offset={off}")
    print(f"msgpack_consumed={consumed}")
    print(f"trailing_bytes={len(raw) - off - consumed}")


def command_scan(
    folder: Path, output_json: Path | None, key_pattern: str | None
) -> None:
    pattern = re.compile(key_pattern) if key_pattern else None
    rows: list[dict[str, Any]] = []

    for file_path in sorted(folder.glob("*.data")):
        try:
            raw = gzip.decompress(file_path.read_bytes())
            off, value, consumed = decode_best(raw)
        except Exception as exc:
            rows.append(
                {
                    "file": file_path.name,
                    "status": "decode_error",
                    "error": str(exc),
                }
            )
            continue

        row: dict[str, Any] = {
            "file": file_path.name,
            "status": "ok",
            "rawLen": len(raw),
            "bestOffset": off,
            "consumed": consumed,
            "trailing": len(raw) - off - consumed,
            "topType": type(value).__name__,
        }

        if isinstance(value, dict):
            keys = list(value.keys())
            row["topKeys"] = keys[:60]
            if pattern:
                row["matchedTopKeys"] = [k for k in keys if pattern.search(str(k))][:60]
        elif isinstance(value, list):
            row["topLen"] = len(value)

        rows.append(row)

    if output_json is None:
        output_json = folder.parent / "useData.scan.json"
    output_json.write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    ok_count = sum(1 for r in rows if r.get("status") == "ok")
    print(f"wrote_scan={output_json}")
    print(f"total={len(rows)}")
    print(f"ok={ok_count}")
    print(f"decode_error={len(rows) - ok_count}")


def command_batch_decode(folder: Path, output_dir: Path, overwrite: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    ok_count = 0
    skip_count = 0
    err_count = 0

    for file_path in sorted(folder.glob("*.data")):
        out_file = output_dir / f"{file_path.name}.json"
        if out_file.exists() and not overwrite:
            skip_count += 1
            rows.append(
                {
                    "file": file_path.name,
                    "status": "skipped",
                    "output": str(out_file),
                }
            )
            continue

        try:
            raw = gzip.decompress(file_path.read_bytes())
            off, value, consumed = decode_best(raw)
            friendly = st.to_json_friendly(value)
            out_file.write_text(
                json.dumps(friendly, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            ok_count += 1
            rows.append(
                {
                    "file": file_path.name,
                    "status": "ok",
                    "output": str(out_file),
                    "rawLen": len(raw),
                    "bestOffset": off,
                    "consumed": consumed,
                    "trailing": len(raw) - off - consumed,
                    "topType": type(value).__name__,
                }
            )
        except Exception as exc:
            err_count += 1
            rows.append(
                {
                    "file": file_path.name,
                    "status": "decode_error",
                    "error": str(exc),
                }
            )

    report_path = output_dir / "_batch_report.json"
    report_path.write_text(
        json.dumps(rows, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"folder={folder}")
    print(f"output_dir={output_dir}")
    print(f"total={len(rows)}")
    print(f"ok={ok_count}")
    print(f"skipped={skip_count}")
    print(f"decode_error={err_count}")
    print(f"report={report_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Decode useData .data files")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="show decode metadata for one .data file")
    p_info.add_argument("file", type=Path)

    p_decode = sub.add_parser("decode", help="decode one .data to JSON")
    p_decode.add_argument("file", type=Path)
    p_decode.add_argument("output", nargs="?", type=Path)

    p_scan = sub.add_parser("scan", help="scan all .data files in folder")
    p_scan.add_argument("folder", type=Path)
    p_scan.add_argument("output", nargs="?", type=Path)
    p_scan.add_argument(
        "--key-pattern", default=None, help="regex for matching top-level keys"
    )

    p_batch = sub.add_parser(
        "batch-decode", help="decode all .data files in folder to JSON files"
    )
    p_batch.add_argument("folder", type=Path)
    p_batch.add_argument("output_dir", type=Path)
    p_batch.add_argument(
        "--overwrite",
        action="store_true",
        help="overwrite existing output JSON files",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "info":
        command_info(args.file)
        return
    if args.cmd == "decode":
        command_decode(args.file, args.output)
        return
    if args.cmd == "scan":
        command_scan(args.folder, args.output, args.key_pattern)
        return
    if args.cmd == "batch-decode":
        command_batch_decode(args.folder, args.output_dir, args.overwrite)
        return
    parser.error("Unknown command")


if __name__ == "__main__":
    main()
