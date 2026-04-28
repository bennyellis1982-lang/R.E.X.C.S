#!/usr/bin/env python3
"""Create size-bounded processing batches for BWC/DVD evidence files."""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BYTES_PER_GB = 1024**3
VIDEO_EXTENSIONS = {
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".m4v",
    ".mpg",
    ".mpeg",
    ".wmv",
    ".asf",
    ".3gp",
    ".vob",
    ".ts",
    ".mts",
    ".m2ts",
}


@dataclass(frozen=True)
class EvidenceFile:
    path: Path
    size_bytes: int

    @property
    def size_gb(self) -> float:
        return self.size_bytes / BYTES_PER_GB


@dataclass
class Batch:
    files: list[EvidenceFile]
    total_bytes: int = 0

    def add(self, file_item: EvidenceFile) -> None:
        self.files.append(file_item)
        self.total_bytes += file_item.size_bytes

    @property
    def total_gb(self) -> float:
        return self.total_bytes / BYTES_PER_GB


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Group BWC/DVD files into deterministic batches under a target size."
    )
    parser.add_argument("source", help="Root folder containing DVD/BWC evidence files")
    parser.add_argument(
        "--target-gb",
        type=float,
        default=3.5,
        help="Maximum target batch size in GB (default: 3.5)",
    )
    parser.add_argument(
        "--include-all-files",
        action="store_true",
        help="Include every regular file instead of only common video formats",
    )
    parser.add_argument(
        "--json-out",
        help="Optional output JSON manifest path",
    )
    parser.add_argument(
        "--csv-out",
        help="Optional output CSV manifest path",
    )
    return parser.parse_args()


def collect_files(source: Path, include_all_files: bool) -> list[EvidenceFile]:
    files: list[EvidenceFile] = []
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        if not include_all_files and path.suffix.lower() not in VIDEO_EXTENSIONS:
            continue
        files.append(EvidenceFile(path=path, size_bytes=path.stat().st_size))

    return sorted(files, key=lambda item: str(item.path.relative_to(source)).lower())


def assign_batches(files: list[EvidenceFile], target_bytes: int) -> list[Batch]:
    batches: list[Batch] = []
    current = Batch(files=[])

    for item in files:
        if item.size_bytes > target_bytes:
            if current.files:
                batches.append(current)
                current = Batch(files=[])
            oversized = Batch(files=[])
            oversized.add(item)
            batches.append(oversized)
            continue

        if current.files and current.total_bytes + item.size_bytes > target_bytes:
            batches.append(current)
            current = Batch(files=[])

        current.add(item)

    if current.files:
        batches.append(current)

    return batches


def ensure_parent(path: Path) -> None:
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def write_json(
    out_path: Path,
    source: Path,
    batches: list[Batch],
    target_gb: float,
    target_bytes: int,
    include_all_files: bool,
) -> None:
    ensure_parent(out_path)
    payload = {
        "source_root": str(source.resolve()),
        "target_gb": target_gb,
        "target_bytes": target_bytes,
        "include_all_files": include_all_files,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "batches": [
            {
                "batch_id": index,
                "total_bytes": batch.total_bytes,
                "total_gb": round(batch.total_gb, 6),
                "file_count": len(batch.files),
                "files": [
                    {
                        "relative_path": str(file_item.path.relative_to(source)),
                        "size_bytes": file_item.size_bytes,
                        "size_gb": round(file_item.size_gb, 6),
                    }
                    for file_item in batch.files
                ],
            }
            for index, batch in enumerate(batches, start=1)
        ],
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(out_path: Path, source: Path, batches: list[Batch]) -> None:
    ensure_parent(out_path)
    with out_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "batch_id",
                "batch_total_bytes",
                "batch_total_gb",
                "batch_file_count",
                "relative_path",
                "size_bytes",
                "size_gb",
            ],
        )
        writer.writeheader()
        for index, batch in enumerate(batches, start=1):
            for file_item in batch.files:
                writer.writerow(
                    {
                        "batch_id": index,
                        "batch_total_bytes": batch.total_bytes,
                        "batch_total_gb": round(batch.total_gb, 6),
                        "batch_file_count": len(batch.files),
                        "relative_path": str(file_item.path.relative_to(source)),
                        "size_bytes": file_item.size_bytes,
                        "size_gb": round(file_item.size_gb, 6),
                    }
                )


def to_human(bytes_count: int) -> str:
    return f"{(bytes_count / BYTES_PER_GB):.3f} GB"


def print_summary(
    source: Path,
    files: list[EvidenceFile],
    batches: list[Batch],
    target_bytes: int,
    include_all_files: bool,
) -> None:
    print("BWC/DVD evidence batching summary")
    print(f"- Source root: {source.resolve()}")
    print(f"- Include all files: {include_all_files}")
    print(f"- File count: {len(files)}")
    print(f"- Total size: {to_human(sum(file_item.size_bytes for file_item in files))}")
    print(f"- Target per batch: {to_human(target_bytes)}")
    print(f"- Batch count: {len(batches)}")
    for index, batch in enumerate(batches, start=1):
        print(
            f"  Batch {index}: {len(batch.files)} files, "
            f"{batch.total_bytes} bytes ({to_human(batch.total_bytes)})"
        )


def main() -> int:
    args = parse_args()
    source = Path(args.source)

    if not source.exists():
        raise SystemExit(f"Source path does not exist: {source}")
    if not source.is_dir():
        raise SystemExit(f"Source path is not a directory: {source}")
    if args.target_gb <= 0:
        raise SystemExit("--target-gb must be greater than 0")

    target_bytes = int(args.target_gb * BYTES_PER_GB)
    files = collect_files(source, args.include_all_files)

    if not files:
        if args.include_all_files:
            raise SystemExit("No regular files found under source path.")
        raise SystemExit(
            "No matching video files found. Use --include-all-files to include non-video evidence files."
        )

    batches = assign_batches(files, target_bytes)
    print_summary(source, files, batches, target_bytes, args.include_all_files)

    if args.json_out:
        json_path = Path(args.json_out)
        write_json(
            json_path,
            source,
            batches,
            args.target_gb,
            target_bytes,
            args.include_all_files,
        )
        print(f"- JSON manifest: {json_path}")

    if args.csv_out:
        csv_path = Path(args.csv_out)
        write_csv(csv_path, source, batches)
        print(f"- CSV manifest: {csv_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
