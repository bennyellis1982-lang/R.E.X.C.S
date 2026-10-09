#!/usr/bin/env python3
"""
nbccs_bridge.py ───────────────────────────────────────────────────────
NBCCS ↔ REX vault synchroniser + validator (enhanced)

Modes:
 - sync    (default): Validate JSON snapshots; copy *valid* JSONs to the vault
                      (NBCCS_MIRROR), mark immutable, and append evidence_index.csv.
 - validate: Validate JSON snapshots only and append validation results to evidence_index.csv
             (no copying).
 - verify  : Check that referenced mirror files exist and match their recorded sha256.
             Optionally attempt a simple repair (re-copy from original NBCCS path).

New/Fixed:
 - `--copy-invalid` for `sync` (docstring previously promised this but CLI lacked it)
 - `--revalidate` to force validating/logging even if an identical (orig,digest) row exists
 - `--dry-run` now suppresses CSV writes for validate/run modes
 - `verify` subcommand to audit the mirror and optionally attempt simple repairs
 - Minor messaging and robustness improvements
"""

from __future__ import annotations
import argparse
import csv
import hashlib
import json
import os
import platform
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple

# Optional jsonschema import
try:
    from jsonschema import Draft7Validator, FormatChecker
except Exception:
    Draft7Validator = None
    FormatChecker = None

BLOCK = 1 << 20  # 1 MiB

# Default locations (override with env or CLI)
VAULT_ROOT_DEFAULT = pathlib.Path(os.getenv("VAULT_ROOT", "/Volumes/VAULT/REX_VAULT_333"))
NBCCS_DIR_DEFAULT = pathlib.Path(os.getenv("NBCCS_DIR", os.path.expanduser("~/NBCCS")))

# --- NBCCS schema (edit to match authoritative schema) ---
NBCCS_SCHEMA = {
    "type": "object",
    "required": ["case_id", "snapshot_time", "version", "payload"],
    "properties": {
        "case_id": {"type": "string"},
        "snapshot_time": {"type": "string", "format": "date-time"},
        "version": {"type": ["string", "number"]},
        "payload": {"type": "object"},
        "authority": {"type": "string"},
        "notes": {"type": "string"},
    },
    "additionalProperties": True,
}


# --- Utilities ---


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(BLOCK), b""):
            h.update(chunk)
    return h.hexdigest()


def iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dirs(path: pathlib.Path):
    path.mkdir(parents=True, exist_ok=True)


# --- Lock ---


class SimpleLock:
    """
    Small lockfile context manager to reduce races on CSV writes.
    Not cluster-safe; suitable for single-host cron usage.
    """
    def __init__(self, lock_path: pathlib.Path, stale_seconds: int = 3600):
        self.lock_path = lock_path
        self.stale_seconds = stale_seconds
        self.fd = None

    def __enter__(self):
        try:
            self.fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(self.fd, f"{os.getpid()}\n".encode())
            return self
        except FileExistsError:
            # check staleness
            try:
                mtime = self.lock_path.stat().st_mtime
                if time.time() - mtime > self.stale_seconds:
                    # stale, remove and try again
                    self.lock_path.unlink()
                    return self.__enter__()
            except FileNotFoundError:
                return self.__enter__()
            raise RuntimeError(f"Lockfile exists: {self.lock_path}")
        except Exception:
            raise

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.fd:
                os.close(self.fd)
            if self.lock_path.exists():
                self.lock_path.unlink()
        except Exception:
            pass


# --- CSV / index helpers ---


def load_existing_digests(index_csv: pathlib.Path) -> Set[Tuple[str, str]]:
    """
    Return set of (original_name, sha256) already logged.
    """
    existing = set()
    if not index_csv.exists():
        return existing
    with index_csv.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            orig = row.get("original_name", "")
            digest = row.get("sha256", "")
            if orig and digest:
                existing.add((orig, digest))
    return existing


def log_index(index_csv: pathlib.Path,
              ts: str,
              src_rel: str,
              src_mtime: str,
              src_size: int,
              stored_rel: str,
              digest: str,
              valid_json: bool,
              validation_errors: Optional[str],
              dry_run: bool = False) -> None:
    """
    Append a CSV row describing the processed file.
    If dry_run True, only print what would be written.
    """
    header = ["timestamp", "original_name", "original_mtime", "original_size",
              "stored_relpath", "sha256", "valid_json", "validation_errors"]
    ensure_dirs(index_csv.parent)
    row = [ts, src_rel, src_mtime, str(src_size), stored_rel or "", digest,
           "true" if valid_json else "false", validation_errors or ""]
    if dry_run:
        print(f"[dry-run] would append CSV row to {index_csv}: {row}")
        return
    lock_path = index_csv.with_suffix(".lock")
    with SimpleLock(lock_path):
        fresh = not index_csv.exists()
        with index_csv.open("a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            if fresh:
                w.writerow(header)
            w.writerow(row)


# --- File ops ---


def copy_atomic(src: pathlib.Path, dst: pathlib.Path, dry_run: bool = False, verbose: bool = False):
    """
    Copy `src` -> `dst` via a temp file in dst.parent and os.replace() for atomicity.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dry_run:
        if verbose:
            print(f"[dry-run] would copy {src} -> {dst}")
        return
    tmp_name = f".{dst.name}.{uuid.uuid4().hex}.tmp"
    tmp_path = dst.parent / tmp_name
    shutil.copy2(src, tmp_path)
    os.replace(tmp_path, dst)


def make_immutable(path: pathlib.Path, verbose: bool = False):
    """
    Try to mark a file immutable: macOS chflags uchg or Linux chattr +i.
    Errors are ignored.
    """
    try:
        system = platform.system()
        if system == "Darwin":
            subprocess.run(["chflags", "uchg", str(path)], check=True)
            if verbose:
                print(f"🔒 chflags uchg applied to {path}")
        elif system == "Linux":
            subprocess.run(["chattr", "+i", str(path)], check=True)
            if verbose:
                print(f"🔒 chattr +i applied to {path}")
        else:
            if verbose:
                print(f"ℹ️  No immutability action for platform {system}")
    except Exception:
        if verbose:
            print(f"⚠️  Could not make immutable: {path} (continuing)")


# --- JSON validation ---


def validate_json_file(path: pathlib.Path, validator: Optional[Draft7Validator] = None) -> Tuple[bool, Optional[str]]:
    """
    Validate JSON parse and optional jsonschema Draft7Validator.
    Returns (is_valid: bool, errors: None|str).
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as e:
        return False, f"JSON parse error: {e}"
    except Exception as e:
        return False, f"Read error: {e}"

    if validator is not None:
        errors = []
        for err in validator.iter_errors(data):
            loc = ".".join([str(x) for x in err.path]) if err.path else "<root>"
            errors.append(f"{loc}: {err.message}")
        if errors:
            return False, "; ".join(errors)
    return True, None


def build_validator_from_file(schema_file: Optional[pathlib.Path], verbose: bool = False):
    if schema_file is None:
        return None
    if Draft7Validator is None:
        raise RuntimeError("jsonschema is required for schema validation. Install with `pip install jsonschema`.")
    with schema_file.open("r", encoding="utf-8") as fh:
        schema = json.load(fh)
    if verbose:
        print(f"ℹ️  Loaded schema from {schema_file}")
    return Draft7Validator(schema, format_checker=FormatChecker())


# --- Actions: sync / validate / verify ---


def sync(nbccs_dir: pathlib.Path, vault_root: pathlib.Path,
         schema_validator: Optional[Draft7Validator] = None,
         copy_invalid: bool = False,
         revalidate: bool = False,
         dry_run: bool = False,
         verbose: bool = False):
    """
    Validate NBCCS JSON files and copy valid ones into vault mirror.
    copy_invalid: if True, copy invalid JSONs too (logged as invalid).
    revalidate: if True, re-validate and re-log entries even if (original,digest) exists.
    """
    MIRROR = vault_root / "NBCCS_MIRROR"
    INDEX_CSV = vault_root / "evidence_index.csv"

    if not nbccs_dir.exists():
        raise FileNotFoundError(f"NBCCS directory not found: {nbccs_dir}")

    ensure_dirs(MIRROR)
    ensure_dirs(vault_root)
    existing = load_existing_digests(INDEX_CSV)

    added = 0
    for path in sorted(nbccs_dir.rglob("*.json")):
        rel = path.relative_to(nbccs_dir)
        src_rel = f"NBCCS/{rel.as_posix()}"
        digest = sha256(path)

        if not revalidate and (src_rel, digest) in existing:
            if verbose:
                print(f"↩️  Skipping unchanged: {rel}")
            continue

        st = path.stat()
        src_mtime = iso_utc(st.st_mtime)
        src_size = st.st_size
        ts = iso_utc_now()

        valid, errors = validate_json_file(path, schema_validator)

        if not valid:
            # log validation failure
            print(f"❌ {rel}  validation failed: {errors}")
            stored_rel = ""
            if copy_invalid:
                stored_dir = MIRROR / rel.parent
                stored_name = f"{ts}_{rel.name}"
                dst = stored_dir / stored_name
                if dry_run:
                    if verbose:
                        print(f"[dry-run] would copy invalid {path} -> {dst}")
                else:
                    if verbose:
                        print(f"[copy-invalid] copying {path} -> {dst}")
                    copy_atomic(path, dst, dry_run=dry_run, verbose=verbose)
                    if not dry_run:
                        make_immutable(dst, verbose=verbose)
                    # store path relative to MIRROR
                    stored_rel = f"NBCCS_MIRROR/{rel.parent.as_posix()}/{stored_name}" if rel.parent.as_posix() != "." else f"NBCCS_MIRROR/{stored_name}"
            # log (or dry-run print)
            log_index(INDEX_CSV, ts, src_rel, src_mtime, src_size, stored_rel, digest, False, errors, dry_run=dry_run)
            added += 1
            continue

        # valid
        stored_dir = MIRROR / rel.parent
        stored_name = f"{ts}_{rel.name}"
        dst = stored_dir / stored_name
        stored_relpath = f"NBCCS_MIRROR/{rel.parent.as_posix()}/{stored_name}" if rel.parent.as_posix() != "." else f"NBCCS_MIRROR/{stored_name}"

        print(f"📥 {rel}  →  {stored_relpath}")
        copy_atomic(path, dst, dry_run=dry_run, verbose=verbose)
        if not dry_run:
            make_immutable(dst, verbose=verbose)
            log_index(INDEX_CSV, ts, src_rel, src_mtime, src_size, stored_relpath, digest, True, None, dry_run=False)
        else:
            # dry-run: don't actually write CSV, but show what we'd log
            log_index(INDEX_CSV, ts, src_rel, src_mtime, src_size, stored_relpath, digest, True, None, dry_run=True)
        added += 1

    print(f"✓ sync complete. {added} file(s) processed.")


def validate_only(nbccs_dir: pathlib.Path, vault_root: pathlib.Path,
                  schema_validator: Optional[Draft7Validator] = None,
                  revalidate: bool = False,
                  dry_run: bool = False,
                  verbose: bool = False):
    """
    Validate only (no copying). If dry_run is True CSV writes are suppressed.
    """
    INDEX_CSV = vault_root / "evidence_index.csv"
    if not nbccs_dir.exists():
        raise FileNotFoundError(f"NBCCS directory not found: {nbccs_dir}")
    ensure_dirs(vault_root)
    existing = load_existing_digests(INDEX_CSV)

    processed = 0
    for path in sorted(nbccs_dir.rglob("*.json")):
        rel = path.relative_to(nbccs_dir)
        src_rel = f"NBCCS/{rel.as_posix()}"
        digest = sha256(path)

        if not revalidate and (src_rel, digest) in existing:
            if verbose:
                print(f"[skip] {rel} (already logged)")
            continue

        try:
            st = path.stat()
            src_mtime = iso_utc(st.st_mtime)
            src_size = st.st_size
        except Exception:
            src_mtime = ""
            src_size = 0

        ok, errors = validate_json_file(path, schema_validator)
        ts = iso_utc_now()
        if ok:
            print(f"✔ {rel} — schema OK")
            log_index(INDEX_CSV, ts, src_rel, src_mtime, src_size, "", digest, True, None, dry_run=dry_run)
        else:
            errmsg = errors or "unknown"
            print(f"✖ {rel} — schema invalid: {errmsg}")
            log_index(INDEX_CSV, ts, src_rel, src_mtime, src_size, "", digest, False, errmsg, dry_run=dry_run)
        processed += 1

    print(f"✓ Validation complete. {processed} file(s) processed.")


def verify(vault_root: pathlib.Path, nbccs_dir: pathlib.Path, repair: bool = False, dry_run: bool = False, verbose: bool = False):
    """
    Verify that files referenced in evidence_index.csv exist in the mirror and match sha256.
    If repair True, and if the original NBCCS/<path> exists, attempt to recopy it to the mirror.
    NOTE: repair is simple — it will create a new mirror copy and append a CSV row for that copy.
    """
    INDEX_CSV = vault_root / "evidence_index.csv"
    MIRROR = vault_root / "NBCCS_MIRROR"

    if not INDEX_CSV.exists():
        print(f"No index CSV found at {INDEX_CSV}")
        return

    problems = []
    checked = 0
    with INDEX_CSV.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            checked += 1
            stored_rel = row.get("stored_relpath", "").strip()
            expected_sha = row.get("sha256", "").strip()
            orig = row.get("original_name", "").strip()  # e.g., NBCCS/cases/123/x.json
            timestamp = row.get("timestamp", "")
            if not stored_rel:
                # nothing to verify for validation-only rows
                continue
            mirror_path = vault_root / stored_rel
            if not mirror_path.exists():
                msg = f"[MISSING] {stored_rel} (recorded at {timestamp})"
                print(msg)
                problems.append((row, "missing"))
                # attempt repair if requested
                if repair:
                    # try to reconstruct original path
                    if orig.startswith("NBCCS/"):
                        orig_rel = orig[len("NBCCS/"):]
                        orig_path = nbccs_dir / orig_rel
                        if orig_path.exists():
                            ts_now = iso_utc_now()
                            new_dst = MIRROR / pathlib.Path(orig_rel).parent / f"{ts_now}_{pathlib.Path(orig_rel).name}"
                            print(f"[repair] recopy from {orig_path} -> {new_dst}")
                            if not dry_run:
                                copy_atomic(orig_path, new_dst, dry_run=False, verbose=verbose)
                                make_immutable(new_dst, verbose=verbose)
                                # append a new row to CSV describing the repair
                                log_index(INDEX_CSV, ts_now, orig, iso_utc(orig_path.stat().st_mtime), orig_path.stat().st_size,
                                          f"{new_dst.relative_to(MIRROR)}", sha256(new_dst), True, "repaired-missing", dry_run=False)
                        else:
                            print(f"  [repair] original source not found: {orig_path}")
                    else:
                        print(f"  [repair] original_name {orig!r} not NBCCS/..., cannot repair automatically")
                continue
            # exists: verify sha
            actual_sha = sha256(mirror_path)
            if actual_sha.lower() != expected_sha.lower():
                print(f"[MISMATCH] {stored_rel} (expected {expected_sha[:8]}..., got {actual_sha[:8]}...)")
                problems.append((row, "mismatch"))
            else:
                if verbose:
                    print(f"[OK] {stored_rel} matches sha")
    print(f"✓ verify complete. {checked} index rows examined. {len(problems)} problem(s) found.")


# --- CLI ---


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nbccs_bridge")
    sub = parser.add_subparsers(dest="cmd", required=False)

    p_sync = sub.add_parser("sync", help="Sync NBCCS JSON files into vault mirror (validate + copy).")
    p_sync.add_argument("--nbccs-dir", "-n", default=str(NBCCS_DIR_DEFAULT), help="Path to local NBCCS directory.")
    p_sync.add_argument("--vault-root", "-v", default=str(VAULT_ROOT_DEFAULT), help="Vault root path.")
    p_sync.add_argument("--schema-file", "-s", default=None, help="Optional JSON Schema file (Draft-7).")
    p_sync.add_argument("--copy-invalid", action="store_true", help="Copy invalid schema files into mirror too.")
    p_sync.add_argument("--revalidate", action="store_true", help="Revalidate even if identical (original,digest) exists in index.")
    p_sync.add_argument("--dry-run", action="store_true", help="Do not write/copy anything; only show actions.")
    p_sync.add_argument("--verbose", action="store_true", help="Verbose output.")

    p_validate = sub.add_parser("validate", help="Validate NBCCS JSON files and append results to CSV (no copy).")
    p_validate.add_argument("--nbccs-dir", "-n", default=str(NBCCS_DIR_DEFAULT), help="Path to local NBCCS directory.")
    p_validate.add_argument("--vault-root", "-v", default=str(VAULT_ROOT_DEFAULT), help="Vault root path.")
    p_validate.add_argument("--schema-file", "-s", default=None, help="Optional JSON Schema file (Draft-7).")
    p_validate.add_argument("--revalidate", action="store_true", help="Revalidate even if identical (original,digest) exists in index.")
    p_validate.add_argument("--dry-run", action="store_true", help="Do not write CSV; show actions only.")
    p_validate.add_argument("--verbose", action="store_true", help="Verbose output.")

    p_verify = sub.add_parser("verify", help="Verify mirror files referenced in evidence_index.csv (existence + sha256).")
    p_verify.add_argument("--vault-root", "-v", default=str(VAULT_ROOT_DEFAULT), help="Vault root path.")
    p_verify.add_argument("--nbccs-dir", "-n", default=str(NBCCS_DIR_DEFAULT), help="NBCCS source dir (used if --repair).")
    p_verify.add_argument("--repair", action="store_true", help="Attempt simple repair by re-copying from NBCCS when mirror is missing.")
    p_verify.add_argument("--dry-run", action="store_true", help="If used with --repair, do not actually write/copy.")
    p_verify.add_argument("--verbose", action="store_true", help="Verbose output.")

    # Backwards compatibility: default to sync if no subcommand given.
    args = parser.parse_args(argv)
    cmd = args.cmd or "sync"

    # normalize paths
    nbccs_dir = pathlib.Path(getattr(args, "nbccs_dir", args.nbccs_dir if hasattr(args, "nbccs_dir") else str(NBCCS_DIR_DEFAULT))).expanduser().resolve()
    vault_root = pathlib.Path(getattr(args, "vault_root", args.vault_root if hasattr(args, "vault_root") else str(VAULT_ROOT_DEFAULT))).expanduser().resolve()
    schema_file = None
    if getattr(args, "schema_file", None):
        schema_file = pathlib.Path(args.schema_file).expanduser().resolve()

    try:
        validator = build_validator_from_file(schema_file, verbose=getattr(args, "verbose", False)) if schema_file else (Draft7Validator(NBCCS_SCHEMA, format_checker=FormatChecker()) if Draft7Validator else None)
    except Exception as e:
        print(f"✖ Schema load error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        if cmd == "sync":
            sync(nbccs_dir=nbccs_dir,
                 vault_root=vault_root,
                 schema_validator=validator,
                 copy_invalid=getattr(args, "copy_invalid", False),
                 revalidate=getattr(args, "revalidate", False),
                 dry_run=getattr(args, "dry_run", False),
                 verbose=getattr(args, "verbose", False))
        elif cmd == "validate":
            validate_only(nbccs_dir=nbccs_dir,
                          vault_root=vault_root,
                          schema_validator=validator,
                          revalidate=getattr(args, "revalidate", False),
                          dry_run=getattr(args, "dry_run", False),
                          verbose=getattr(args, "verbose", False))
        elif cmd == "verify":
            verify(vault_root=vault_root,
                   nbccs_dir=nbccs_dir,
                   repair=getattr(args, "repair", False),
                   dry_run=getattr(args, "dry_run", False),
                   verbose=getattr(args, "verbose", False))
        else:
            parser.print_help()
    except Exception as e:
        print(f"✖ Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
