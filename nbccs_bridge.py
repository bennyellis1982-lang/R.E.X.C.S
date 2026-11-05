from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path
from typing import Any, Callable


Validator = Callable[[dict[str, Any]], Any] | None


def validate_json_file(path: Path, validator: Validator = None) -> tuple[bool, str | None]:
    """Validate that a file is parseable JSON and optionally schema-valid."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except json.JSONDecodeError as exc:
        return False, f"JSON parse error: {exc}"
    except OSError as exc:
        return False, f"File read error: {exc}"

    if validator is None:
        return True, None

    try:
        result = validator(payload)
    except Exception as exc:  # validators may raise varied exception types
        return False, str(exc)

    if result in (None, True, ""):
        return True, None

    if result is False:
        return False, "Schema validation failed"

    if isinstance(result, str):
        return False, result

    if isinstance(result, (list, tuple, set)):
        return False, "; ".join(str(item) for item in result)

    return False, str(result)


def _iter_json_files(root: Path):
    for path in sorted(root.rglob("*.json")):
        if path.is_file():
            yield path


def _write_index(index_path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = ["original_name", "stored_relpath", "valid_json", "validation_errors"]
    with index_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def sync(
    nbccs_dir: Path,
    vault_root: Path,
    schema_validator: Validator = None,
    mode: str = "sync",
    dry_run: bool = False,
    verbose: bool = False,
) -> None:
    """Validate and optionally sync NBCCS JSON artifacts into a vault mirror."""
    nbccs_dir = Path(nbccs_dir)
    vault_root = Path(vault_root)
    mirror_root = vault_root / "NBCCS_MIRROR"
    mirror_root.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, str]] = []

    for source in _iter_json_files(nbccs_dir):
        rel = source.relative_to(nbccs_dir)
        original_name = Path("NBCCS") / rel

        valid, error = validate_json_file(source, validator=schema_validator)
        stored_relpath = ""

        if mode == "sync" and valid and not dry_run:
            destination = mirror_root / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            stored_relpath = str(destination.relative_to(vault_root)).replace("\\", "/")

        row = {
            "original_name": str(original_name).replace("\\", "/"),
            "stored_relpath": stored_relpath,
            "valid_json": "true" if valid else "false",
            "validation_errors": "" if error is None else error,
        }
        rows.append(row)

        if verbose:
            print(f"{row['original_name']}: valid={row['valid_json']}")

    should_write_csv = (mode == "validate" and not dry_run) or (mode == "sync" and not dry_run)
    if should_write_csv:
        _write_index(vault_root / "evidence_index.csv", rows)
