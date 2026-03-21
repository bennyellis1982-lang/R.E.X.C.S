#!/usr/bin/env python3
"""Create size-bounded processing batches for BWC/DVD evidence files."""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path

VIDEO_EXTENSIONS = {
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".wmv",
    ".m4v",
    ".mpg",
    ".mpeg",
    ".mts",
    ".m2ts",
    ".vob",
}


@dataclass
class EvidenceFile:
    path: Path
    size_bytes: int


@dataclass
class Batch:
    files: list[EvidenceFile]
    size_bytes: int = 0

    def add(self, file_item: EvidenceFile) -> None:
        self.files.append(file_item)
        self.size_bytes += file_item.size_bytes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Group BWC/DVD files into batches under a target size."
    )
    parser.add_argument("source", help="Root folder containing DVD/BWC files")
    parser.add_argument(
        "--target-gb",
        type=float,
        default=3.5,
        help="Maximum batch size in GB (default: 3.5)",
    )
    parser.add_argument(
        "--include-all-files",
        action="store_true",
        help="Include every file type instead of only common video formats",
    )
    parser.add_argument(
        "--json-out",
        default="bwc_batch_manifest.json",
        help="Output JSON manifest path",
    )
    parser.add_argument(
        "--csv-out",
        default="bwc_batch_manifest.csv",
        help="Output CSV manifest path",
    )
    return parser.parse_args()


def collect_files(source: Path, include_all_files: bool) -> list[EvidenceFile]:
    files: list[EvidenceFile] = []
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        if not include_all_files and path.suffix.lower() not in VIDEO_EXTENSIONS:
            continue
        files.append(EvidenceFile(path=path, size_bytes=path.stat().st_size))
    return files


def assign_batches(files: list[EvidenceFile], target_bytes: int) -> list[Batch]:
    batches: list[Batch] = []
    current = Batch(files=[])

    for item in files:
        if current.files and current.size_bytes + item.size_bytes > target_bytes:
            batches.append(current)
            current = Batch(files=[])
        current.add(item)

    if current.files:
        batches.append(current)
    return batches


def to_human(bytes_count: int) -> str:
    gb = bytes_count / (1024**3)
    return f"{gb:.2f} GB"


def write_json(out_path: Path, source: Path, batches: list[Batch], target_bytes: int) -> None:
    payload = {
        "source": str(source.resolve()),
        "target_batch_size_bytes": target_bytes,
        "batch_count": len(batches),
        "batches": [
            {
                "batch_id": index,
                "size_bytes": batch.size_bytes,
                "size_human": to_human(batch.size_bytes),
                "file_count": len(batch.files),
                "files": [
                    {
                        "relative_path": str(file_item.path.relative_to(source)),
                        "size_bytes": file_item.size_bytes,
                    }
                    for file_item in batch.files
                ],
            }
            for index, batch in enumerate(batches, start=1)
        ],
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(out_path: Path, source: Path, batches: list[Batch]) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=["batch_id", "file_count_in_batch", "batch_size_bytes", "relative_path", "file_size_bytes"],
        )
        writer.writeheader()
        for index, batch in enumerate(batches, start=1):
            for file_item in batch.files:
                writer.writerow(
                    {
                        "batch_id": index,
                        "file_count_in_batch": len(batch.files),
                        "batch_size_bytes": batch.size_bytes,
                        "relative_path": str(file_item.path.relative_to(source)),
                        "file_size_bytes": file_item.size_bytes,
                    }
                )


def main() -> int:
    args = parse_args()
    source = Path(args.source)

    if not source.exists() or not source.is_dir():
        raise SystemExit(f"Source folder not found or not a directory: {source}")

    target_bytes = int(args.target_gb * (1024**3))
    files = collect_files(source, args.include_all_files)

    if not files:
        raise SystemExit(
            "No matching files found. Use --include-all-files to include non-video files."
        )

    batches = assign_batches(files, target_bytes)
    json_path = Path(args.json_out)
    csv_path = Path(args.csv_out)

    write_json(json_path, source, batches, target_bytes)
    write_csv(csv_path, source, batches)

    total_size = sum(file_item.size_bytes for file_item in files)
    print(f"Found {len(files)} files, total {to_human(total_size)}")
    print(f"Created {len(batches)} batches with target {to_human(target_bytes)} each")
    print(f"JSON manifest: {json_path}")
    print(f"CSV manifest: {csv_path}")

    for i, batch in enumerate(batches, start=1):
        print(f"  Batch {i}: {len(batch.files)} files / {to_human(batch.size_bytes)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
