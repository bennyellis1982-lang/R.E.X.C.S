#!/usr/bin/env python3
"""
Rex Recon v2.0 - Enhanced Forensic Recon + Integrity Verification
- Scans target path recursively
- Generates SHA-256 for every file
- Detects corruption (hash mismatch if baseline exists)
- Spots patterns: suspicious timestamps, AAA headers, etc.
- Logs everything structured (txt + CSV summary)
- Hardened: read-only by default, no mods
- Hooks into master heartbeat.py (stub)
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

# Config
LOG_DIR = Path.home() / ".rex_recon"
LOG_DIR.mkdir(exist_ok=True)
BASELINE_FILE = LOG_DIR / "baseline_hashes.json"  # For drift detection
SUSPICIOUS_YEARS = (1970, 1980, 1999, 2038)
AAA_HEADER = b"AAA"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rex Recon v2.0 forensic scanner with per-file hashes, "
            "baseline drift detection, and anomaly logging."
        )
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to scan recursively (default: current directory).",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write/refresh the hash baseline after the scan completes.",
    )
    parser.add_argument(
        "--max-size-mb",
        type=float,
        default=100.0,
        help="Skip files larger than this value in MB (default: 100).",
    )
    return parser.parse_args()


def now_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")


def compute_sha256(file_path: Path) -> str:
    sha256 = hashlib.sha256()
    try:
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as exc:  # noqa: BLE001
        return f"ERROR: {exc}"


def load_baseline() -> dict[str, str]:
    if not BASELINE_FILE.exists():
        return {}
    try:
        with BASELINE_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:  # noqa: BLE001
        return {}
    return {}


def save_baseline(baseline: dict[str, str]) -> None:
    with BASELINE_FILE.open("w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2, sort_keys=True)


def is_suspicious_timestamp(stat_result: os.stat_result) -> bool:
    mtime_year = dt.datetime.fromtimestamp(stat_result.st_mtime, tz=dt.timezone.utc).year
    return mtime_year in SUSPICIOUS_YEARS


def has_aaa_header(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(3) == AAA_HEADER
    except Exception:  # noqa: BLE001
        return False


def heartbeat_stub(payload: dict[str, Any]) -> None:
    """Stub hook to master_heartbeat.py for later integration."""
    _ = payload


def scan_file(path: Path, baseline: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "size": None,
        "mtime": None,
        "sha256": None,
        "status": "ok",
        "baseline_match": None,
        "suspicious_timestamp": False,
        "aaa_header": False,
        "error": "",
    }

    try:
        stat_result = path.stat()
        result["size"] = stat_result.st_size
        result["mtime"] = dt.datetime.fromtimestamp(
            stat_result.st_mtime,
            tz=dt.timezone.utc,
        ).isoformat()
        result["suspicious_timestamp"] = is_suspicious_timestamp(stat_result)
    except Exception as exc:  # noqa: BLE001
        result["status"] = "stat_error"
        result["error"] = str(exc)
        return result

    digest = compute_sha256(path)
    result["sha256"] = digest
    if digest.startswith("ERROR:"):
        result["status"] = "hash_error"
        result["error"] = digest
        return result

    expected = baseline.get(str(path))
    if expected is None:
        result["baseline_match"] = None
    else:
        result["baseline_match"] = digest == expected
        if digest != expected:
            result["status"] = "corrupt_or_modified"

    result["aaa_header"] = has_aaa_header(path)
    if result["aaa_header"] and result["status"] == "ok":
        result["status"] = "suspicious_header"

    return result


def run() -> int:
    args = parse_args()
    target = Path(args.target).expanduser().resolve()
    max_size_bytes = int(args.max_size_mb * 1024 * 1024)

    if not target.exists():
        raise SystemExit(f"Target does not exist: {target}")

    timestamp = now_stamp()
    txt_log_path = LOG_DIR / f"recon_{timestamp}.txt"
    csv_log_path = LOG_DIR / f"recon_{timestamp}.csv"

    baseline = load_baseline()
    new_baseline: dict[str, str] = {}

    totals = {
        "scanned": 0,
        "corrupt_or_modified": 0,
        "suspicious_timestamp": 0,
        "suspicious_header": 0,
        "errors": 0,
        "skipped_large": 0,
    }

    with txt_log_path.open("w", encoding="utf-8") as txt_log, csv_log_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as csv_log:
        writer = csv.DictWriter(
            csv_log,
            fieldnames=[
                "path",
                "size",
                "mtime",
                "sha256",
                "status",
                "baseline_match",
                "suspicious_timestamp",
                "aaa_header",
                "error",
            ],
        )
        writer.writeheader()

        for root, _, files in os.walk(target):
            for filename in files:
                path = Path(root) / filename
                try:
                    if path.stat().st_size > max_size_bytes:
                        totals["skipped_large"] += 1
                        continue
                except Exception:
                    pass

                record = scan_file(path, baseline)
                totals["scanned"] += 1

                if record["sha256"] and not str(record["sha256"]).startswith("ERROR:"):
                    new_baseline[str(path)] = str(record["sha256"])

                if record["status"] == "corrupt_or_modified":
                    totals["corrupt_or_modified"] += 1
                if record["suspicious_timestamp"]:
                    totals["suspicious_timestamp"] += 1
                if record["aaa_header"]:
                    totals["suspicious_header"] += 1
                if record["error"]:
                    totals["errors"] += 1

                writer.writerow(record)
                txt_log.write(json.dumps(record, sort_keys=True) + "\n")

    summary = {
        "target": str(target),
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "txt_log": str(txt_log_path),
        "csv_log": str(csv_log_path),
        **totals,
    }

    heartbeat_stub(summary)

    if args.update_baseline:
        save_baseline(new_baseline)
        summary["baseline_updated"] = True
    else:
        summary["baseline_updated"] = False

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
