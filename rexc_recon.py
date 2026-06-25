#!/usr/bin/env python3
"""R.EX.C.S Recon Utility: Full Disk Pattern Recon + SHA Logger."""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sys
from typing import Iterator, Optional


@dataclasses.dataclass
class ReconMatch:
    path: str
    size: int
    mtime: str
    sha256: str
    path_match: bool
    content_match: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan filesystem paths for pattern matches and log SHA-256 hashes."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default="/",
        help="Root directory to scan (default: /)",
    )
    parser.add_argument(
        "--pattern",
        required=True,
        help="Regex pattern to match against file paths.",
    )
    parser.add_argument(
        "--content",
        help="Optional regex pattern to search within file contents.",
    )
    parser.add_argument(
        "--output",
        default="rexc_recon_log.jsonl",
        help="Path to write JSONL output (default: rexc_recon_log.jsonl)",
    )
    parser.add_argument(
        "--max-size-mb",
        type=float,
        default=50.0,
        help="Skip files larger than this size in MB (default: 50)",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symlinks while walking directories.",
    )
    parser.add_argument(
        "--include-hidden",
        action="store_true",
        help="Include hidden files and directories.",
    )
    return parser.parse_args()


def iter_files(root: str, follow_symlinks: bool, include_hidden: bool) -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        if not include_hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            filenames = [f for f in filenames if not f.startswith(".")]
        for filename in filenames:
            yield os.path.join(dirpath, filename)


def sha256_file(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def file_content_matches(path: str, pattern: re.Pattern[bytes]) -> bool:
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if pattern.search(chunk):
                return True
    return False


def file_metadata(path: str) -> tuple[int, str]:
    stat = os.stat(path)
    size = stat.st_size
    mtime = dt.datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z"
    return size, mtime


def match_file(
    path: str,
    path_pattern: re.Pattern[str],
    content_pattern: Optional[re.Pattern[bytes]],
    max_size_bytes: int,
) -> Optional[ReconMatch]:
    try:
        size, mtime = file_metadata(path)
    except (OSError, PermissionError):
        return None

    if size > max_size_bytes:
        return None

    path_match = bool(path_pattern.search(path))
    content_match = False

    if content_pattern is not None:
        try:
            content_match = file_content_matches(path, content_pattern)
        except (OSError, PermissionError):
            return None

    if not path_match and not content_match:
        return None

    try:
        digest = sha256_file(path)
    except (OSError, PermissionError):
        return None

    return ReconMatch(
        path=path,
        size=size,
        mtime=mtime,
        sha256=digest,
        path_match=path_match,
        content_match=content_match,
    )


def run() -> int:
    args = parse_args()
    path_pattern = re.compile(args.pattern)
    content_pattern = re.compile(args.content.encode()) if args.content else None
    max_size_bytes = int(args.max_size_mb * 1024 * 1024)

    total_scanned = 0
    total_matched = 0

    with open(args.output, "w", encoding="utf-8") as output:
        for path in iter_files(args.root, args.follow_symlinks, args.include_hidden):
            total_scanned += 1
            match = match_file(path, path_pattern, content_pattern, max_size_bytes)
            if match is None:
                continue
            total_matched += 1
            output.write(json.dumps(dataclasses.asdict(match)) + "\n")

    print(
        f"Recon complete. Scanned {total_scanned} files, logged {total_matched} matches.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
