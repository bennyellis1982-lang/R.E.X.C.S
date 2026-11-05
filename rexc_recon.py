#!/usr/bin/env python3
"""REX Recon: deterministic, read-only file integrity reconnaissance."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable

SUSPICIOUS_YEARS = {1970, 1980, 1999, 2038}
AAA_HEADER = b"AAA"
BASELINE_SCHEMA = "rex-recon-baseline/1"
CSV_FIELDS = [
    "relative_path", "size_bytes", "mtime_utc", "sha256", "status",
    "baseline_match", "suspicious_timestamp", "aaa_header", "content_match", "error",
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only SHA-256 recon with portable baseline drift detection."
    )
    parser.add_argument("target", nargs="?", default=".")
    parser.add_argument("--pattern", help="Regex matched against relative file paths.")
    parser.add_argument("--content", help="Optional UTF-8 text or regex to locate in matched files.")
    parser.add_argument("--content-regex", action="store_true")
    parser.add_argument("--max-size-mb", type=float, default=100.0)
    parser.add_argument("--output", type=Path, help="Explicit JSONL record output path.")
    parser.add_argument("--output-dir", type=Path, default=Path.home() / ".rex_recon")
    parser.add_argument("--baseline", type=Path, help="Portable baseline JSON path.")
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--fail-on-drift", action="store_true")
    parser.add_argument("--include-symlinks", action="store_true")
    args = parser.parse_args(argv)
    if args.max_size_mb <= 0:
        parser.error("--max-size-mb must be greater than zero")
    return args


def now_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, indent=2, sort_keys=True)
            file_obj.write("\n")
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_baseline(path: Path | None, target: Path) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("baseline must be a JSON object")
    if payload.get("schema") == BASELINE_SCHEMA:
        files = payload.get("files")
        if not isinstance(files, dict):
            raise ValueError("baseline files must be a JSON object")
        return {str(key): str(value) for key, value in files.items()}
    compatible: dict[str, str] = {}
    for key, value in payload.items():
        old_path = Path(str(key))
        if old_path.is_absolute():
            try:
                key = old_path.relative_to(target).as_posix()
            except ValueError:
                continue
        compatible[str(key)] = str(value)
    return compatible


def save_baseline(path: Path, target: Path, hashes: dict[str, str]) -> None:
    atomic_json(path, {
        "schema": BASELINE_SCHEMA,
        "target_at_creation": str(target),
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "files": dict(sorted(hashes.items())),
    })


def iter_files(target: Path, include_symlinks: bool) -> Iterable[Path]:
    if target.is_file():
        if include_symlinks or not target.is_symlink():
            yield target
        return
    for root, directories, filenames in os.walk(target, followlinks=False):
        directories[:] = sorted(
            directory for directory in directories
            if include_symlinks or not (Path(root) / directory).is_symlink()
        )
        for filename in sorted(filenames):
            path = Path(root) / filename
            if include_symlinks or not path.is_symlink():
                yield path


def content_matches(path: Path, needle: str | None, use_regex: bool) -> bool | None:
    if needle is None:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(needle, text)) if use_regex else needle in text


def scan_file(
    path: Path, target: Path, baseline: dict[str, str],
    content: str | None, content_regex: bool,
) -> dict[str, Any]:
    relative_path = path.name if target.is_file() else path.relative_to(target).as_posix()
    record: dict[str, Any] = {
        "relative_path": relative_path, "size_bytes": None, "mtime_utc": None,
        "sha256": None, "status": "ok", "baseline_match": None,
        "suspicious_timestamp": False, "aaa_header": False,
        "content_match": None, "error": "",
    }
    try:
        before = path.stat()
        digest = sha256_file(path)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            record["status"] = "changed_during_scan"
        record["size_bytes"] = after.st_size
        record["mtime_utc"] = dt.datetime.fromtimestamp(
            after.st_mtime, tz=dt.timezone.utc
        ).isoformat()
        record["sha256"] = digest
        year = dt.datetime.fromtimestamp(after.st_mtime, tz=dt.timezone.utc).year
        record["suspicious_timestamp"] = year in SUSPICIOUS_YEARS
        with path.open("rb") as file_obj:
            record["aaa_header"] = file_obj.read(3) == AAA_HEADER
        record["content_match"] = content_matches(path, content, content_regex)
        expected = baseline.get(relative_path)
        if expected is not None:
            record["baseline_match"] = digest == expected
            if digest != expected:
                record["status"] = "modified_since_baseline"
        if record["aaa_header"] and record["status"] == "ok":
            record["status"] = "suspicious_header"
    except OSError as error:
        record["status"] = "read_error"
        record["error"] = str(error)
    return record


def run(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        raise SystemExit(f"Target does not exist: {target}")

    path_pattern = re.compile(args.pattern) if args.pattern else None
    if args.content_regex and args.content:
        re.compile(args.content)
    output_dir = args.output_dir.expanduser().resolve()
    stamp = now_stamp()
    jsonl_path = (args.output or output_dir / f"recon_{stamp}.jsonl").expanduser().resolve()
    csv_path = output_dir / f"recon_{stamp}.csv"
    summary_path = output_dir / f"recon_{stamp}.summary.json"
    baseline_path = args.baseline.expanduser().resolve() if args.baseline else None
    if args.update_baseline and baseline_path is None:
        baseline_path = output_dir / "baseline_hashes.json"

    baseline = load_baseline(baseline_path, target)
    current_hashes: dict[str, str] = {}
    records: list[dict[str, Any]] = []
    skipped_large = 0
    max_bytes = int(args.max_size_mb * 1024 * 1024)
    excluded_paths = {jsonl_path, csv_path, summary_path}
    if baseline_path is not None:
        excluded_paths.add(baseline_path)

    for path in iter_files(target, args.include_symlinks):
        resolved_path = path.resolve()
        output_tree = False
        if output_dir != target:
            try:
                resolved_path.relative_to(output_dir)
                output_tree = True
            except ValueError:
                pass
        if output_tree or resolved_path in excluded_paths:
            continue
        relative = path.name if target.is_file() else path.relative_to(target).as_posix()
        if path_pattern and not path_pattern.search(relative):
            continue
        try:
            if path.stat().st_size > max_bytes:
                skipped_large += 1
                continue
        except OSError:
            pass
        record = scan_file(path, target, baseline, args.content, args.content_regex)
        records.append(record)
        if record["sha256"]:
            current_hashes[relative] = str(record["sha256"])

    skipped_symlinks = 0
    if target.is_dir() and not args.include_symlinks:
        skipped_symlinks = sum(1 for path in target.rglob("*") if path.is_symlink())
    missing = sorted(set(baseline) - set(current_hashes))
    counts: dict[str, int] = {}
    for record in records:
        counts[record["status"]] = counts.get(record["status"], 0) + 1

    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("w", encoding="utf-8") as file_obj:
        for record in records:
            file_obj.write(json.dumps(record, sort_keys=True) + "\n")
    with csv_path.open("w", newline="", encoding="utf-8") as file_obj:
        writer = csv.DictWriter(file_obj, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(records)

    if args.update_baseline and baseline_path is not None:
        save_baseline(baseline_path, target, current_hashes)

    summary = {
        "schema": "rex-recon-summary/1", "target": str(target),
        "completed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "records": len(records), "status_counts": counts,
        "missing_since_baseline": missing, "skipped_large": skipped_large,
        "skipped_symlinks": skipped_symlinks,
        "baseline": str(baseline_path) if baseline_path else None,
        "baseline_updated": bool(args.update_baseline), "jsonl_log": str(jsonl_path),
        "csv_log": str(csv_path), "summary_log": str(summary_path),
    }
    atomic_json(summary_path, summary)
    print(json.dumps(summary, indent=2))
    drift = counts.get("modified_since_baseline", 0) or missing
    return 2 if args.fail_on_drift and drift else 0


if __name__ == "__main__":
    raise SystemExit(run())
