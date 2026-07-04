#!/usr/bin/env python3
"""Build a safe REX Master Vault 333 inventory and review workspace.

This utility is intentionally conservative: it copies matching files into a
staged vault, writes manifests and receipts, and never deletes source files.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

REX_NEEDLE = "rex"
WEB_EXTENSIONS = {".html", ".htm", ".js", ".jsx", ".css"}
CONFIG_EXTENSIONS = {".env", ".ini", ".toml", ".yaml", ".yml", ".json", ".plist"}
LOG_EXTENSIONS = {".log", ".jsonl", ".txt", ".md"}
SOURCE_EXTENSIONS = {".py", ".sh", ".ts", ".tsx", ".sql", ".rs", ".go", ".java", ".rb"}
JUNK_NAMES = {".ds_store", "thumbs.db", "desktop.ini"}
GENERATED_PARTS = {"node_modules", "dist", "build", ".vite", "__pycache__", ".pytest_cache"}

VAULT_FOLDERS = [
    "00_FRONT_DOOR_START_HERE",
    "01_RUNNING_CANDIDATES",
    "02_REX_CLOUD_WIDGETS_HTML",
    "03_REXCAT_CATALINA",
    "04_SOURCE_CODE_FULL_COPY",
    "05_CONFIG_ENV_SENSITIVE_REVIEW",
    "06_LOGS_TERMINAL_NOTES",
    "07_PLACEHOLDER_DEAD_REVIEW_NOT_DELETED",
    "09_ZIPS",
    "10_GHOST_REX_DELETE_REVIEW",
    "11_DELETION_RECEIPTS",
]


@dataclass(frozen=True)
class InventoryItem:
    source_path: str
    relative_path: str
    destination_path: str
    bucket: str
    size_bytes: int
    modified_utc: str
    sha256: str
    ghost_tag: str
    reason: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_root_label(root: Path) -> str:
    resolved = root.expanduser().resolve()
    if resolved.name:
        return resolved.name.replace(" ", "_")
    return "root"


def is_generated(path: Path) -> bool:
    return any(part.lower() in GENERATED_PARTS for part in path.parts)


def is_rex_related(path: Path) -> bool:
    lowered = str(path).lower()
    return REX_NEEDLE in lowered


def classify_bucket(path: Path) -> str:
    lowered = str(path).lower()
    suffix = path.suffix.lower()
    name = path.name.lower()

    if "rexcat" in lowered or "catalina" in lowered or "gemini" in lowered:
        return "03_REXCAT_CATALINA"
    if suffix in WEB_EXTENSIONS or name in {"app.jsx", "vite.config.js", "package.json"}:
        return "02_REX_CLOUD_WIDGETS_HTML"
    if name.startswith(".env") or suffix in CONFIG_EXTENSIONS or "config" in lowered:
        return "05_CONFIG_ENV_SENSITIVE_REVIEW"
    if suffix in LOG_EXTENSIONS or "log" in lowered or "note" in lowered:
        return "06_LOGS_TERMINAL_NOTES"
    if suffix in SOURCE_EXTENSIONS or "dockerfile" == name:
        return "04_SOURCE_CODE_FULL_COPY"
    return "01_RUNNING_CANDIDATES"


def ghost_tag(path: Path, size_bytes: int) -> tuple[str, str]:
    name = path.name.lower()
    if size_bytes == 0:
        return "REVIEW_EMPTY_FILE", "zero-byte file; review before deletion"
    if name in JUNK_NAMES:
        return "SAFE_TO_DELETE_AFTER_ZIP", "known operating-system junk file"
    if is_generated(path):
        return "REVIEW_GENERATED_ARTIFACT", "appears inside generated/cache/build directory"
    return "KEEP", "user or project material"


def iter_files(roots: Iterable[Path], include_all_web: bool) -> Iterable[tuple[Path, Path]]:
    for root in roots:
        root = root.expanduser()
        if not root.exists():
            continue
        if root.is_file():
            if is_rex_related(root) or (include_all_web and root.suffix.lower() in WEB_EXTENSIONS):
                yield root.parent, root
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if is_rex_related(path) or (include_all_web and path.suffix.lower() in WEB_EXTENSIONS):
                yield root, path


def unique_destination(build_root: Path, bucket: str, root: Path, path: Path) -> Path:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(path.name)
    base = build_root / bucket / safe_root_label(root) / rel
    if not base.exists():
        return base
    stem = base.stem
    suffix = base.suffix
    parent = base.parent
    counter = 1
    while True:
        candidate = parent / f"{stem}__copy{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def write_csv(path: Path, rows: list[InventoryItem]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=list(asdict(rows[0]).keys()) if rows else [
            "source_path", "relative_path", "destination_path", "bucket", "size_bytes",
            "modified_utc", "sha256", "ghost_tag", "reason",
        ])
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def append_action_log(path: Path, event: str, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts_utc": utc_now(), "event": event, **payload}
    with path.open("a", encoding="utf-8") as file_obj:
        file_obj.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")


def create_zip(build_root: Path) -> Path:
    zip_dir = build_root / "09_ZIPS"
    zip_dir.mkdir(parents=True, exist_ok=True)
    zip_path = zip_dir / f"REX_Master_Vault_333_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in build_root.rglob("*"):
            if path == zip_path or path.is_dir() or path.name == ".DS_Store":
                continue
            archive.write(path, path.relative_to(build_root))
    return zip_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inventory REX files, stage a Master Vault 333 review tree, and write ghost-file receipts."
    )
    parser.add_argument("roots", nargs="+", help="Local or synced cloud roots to scan, such as ~/Desktop ~/Downloads ~/Google Drive")
    parser.add_argument("--vault-root", default="REX_MASTER_VAULT_333", help="Target vault folder (default: ./REX_MASTER_VAULT_333)")
    parser.add_argument("--build-label", help="Optional BUILD_* folder name. Defaults to UTC timestamp.")
    parser.add_argument("--include-all-web", action="store_true", help="Also collect HTML/JS/JSX/CSS files even if their path does not contain rex.")
    parser.add_argument("--zip", action="store_true", help="Create a zip archive under 09_ZIPS after staging.")
    parser.add_argument("--dry-run", action="store_true", help="Write manifests only; do not copy files or create zip archive.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    roots = [Path(root) for root in args.roots]
    build_label = args.build_label or f"BUILD_{datetime.now(timezone.utc).strftime('%Y-%m-%d_%Y%m%d_%H%M')}"
    vault_root = Path(args.vault_root).expanduser()
    build_root = vault_root / build_label

    for folder in VAULT_FOLDERS:
        if not args.dry_run:
            (build_root / folder).mkdir(parents=True, exist_ok=True)

    action_log = build_root / "00_FRONT_DOOR_START_HERE" / "actions.jsonl"
    rows: list[InventoryItem] = []
    seen_sources: set[Path] = set()

    for root, path in sorted(iter_files(roots, args.include_all_web), key=lambda item: str(item[1]).lower()):
        resolved = path.resolve()
        if resolved in seen_sources:
            continue
        seen_sources.add(resolved)
        stat = path.stat()
        digest = sha256_file(path)
        tag, reason = ghost_tag(path, stat.st_size)
        bucket = "10_GHOST_REX_DELETE_REVIEW" if tag != "KEEP" else classify_bucket(path)
        destination = unique_destination(build_root, bucket, root, path)
        try:
            relative = str(path.relative_to(root))
        except ValueError:
            relative = path.name
        item = InventoryItem(
            source_path=str(path.resolve()),
            relative_path=relative,
            destination_path=str(destination),
            bucket=bucket,
            size_bytes=stat.st_size,
            modified_utc=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            sha256=digest,
            ghost_tag=tag,
            reason=reason,
        )
        rows.append(item)

        if not args.dry_run:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            append_action_log(action_log, "file_copied", asdict(item))
            if tag != "KEEP":
                receipt = build_root / "11_DELETION_RECEIPTS" / f"{digest[:16]}_{path.name}.txt"
                receipt.write_text(
                    "REX Master Vault 333 deletion review receipt\n"
                    f"File: {path.resolve()}\n"
                    f"SHA-256: {digest}\n"
                    f"Size: {stat.st_size} bytes\n"
                    f"Modified UTC: {item.modified_utc}\n"
                    f"Reason: {reason}\n"
                    f"Action: {tag} (no deletion performed by this tool)\n",
                    encoding="utf-8",
                )

    duplicate_groups = [
        {"sha256": digest, "files": sorted(paths)}
        for digest, paths in sorted(
            {
                row.sha256: [item.source_path for item in rows if item.sha256 == row.sha256]
                for row in rows
            }.items()
        )
        if len(paths) > 1
    ]

    manifest_payload = {
        "generated_at_utc": utc_now(),
        "vault_root": str(vault_root.resolve()),
        "build_root": str(build_root.resolve()),
        "roots": [str(root.expanduser()) for root in roots],
        "dry_run": args.dry_run,
        "file_count": len(rows),
        "duplicate_group_count": len(duplicate_groups),
        "duplicate_groups": duplicate_groups,
        "items": [asdict(row) for row in rows],
    }

    manifest_json = build_root / "00_FRONT_DOOR_START_HERE" / "rex_master_vault_inventory.json"
    manifest_csv = build_root / "00_FRONT_DOOR_START_HERE" / "rex_master_vault_inventory.csv"
    duplicates_json = build_root / "00_FRONT_DOOR_START_HERE" / "rex_master_vault_duplicates.json"
    if args.dry_run:
        build_root.mkdir(parents=True, exist_ok=True)
        (build_root / "00_FRONT_DOOR_START_HERE").mkdir(parents=True, exist_ok=True)
    write_json(manifest_json, manifest_payload)
    write_json(duplicates_json, {"generated_at_utc": utc_now(), "duplicate_groups": duplicate_groups})
    write_csv(manifest_csv, rows)

    zip_path = None
    if args.zip and not args.dry_run:
        zip_path = create_zip(build_root)
        append_action_log(action_log, "zip_created", {"zip_path": str(zip_path), "sha256": sha256_file(zip_path)})

    print("REX Master Vault 333 staging summary")
    print(f"- Build root: {build_root}")
    print(f"- Files inventoried: {len(rows)}")
    print(f"- Manifest JSON: {manifest_json}")
    print(f"- Manifest CSV: {manifest_csv}")
    print(f"- Duplicate groups: {len(duplicate_groups)}")
    if zip_path:
        print(f"- Zip archive: {zip_path}")
    print("- Source deletions performed: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
