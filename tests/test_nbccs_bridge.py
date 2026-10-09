import csv
import json
import pathlib
import sys

# Ensure repository root is importable
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import nbccs_bridge as nb  # noqa: E402


def write_json(path: pathlib.Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def write_text(path: pathlib.Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(text)


def read_csv_rows(path: pathlib.Path):
    rows = []
    with path.open("r", newline="", encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        for row in r:
            rows.append(row)
    return rows


def test_validate_json_file_good(tmp_path):
    p = tmp_path / "good.json"
    obj = {"case_id": "X", "snapshot_time": "2025-01-01T00:00:00Z", "version": "1", "payload": {}}
    write_json(p, obj)

    valid, err = nb.validate_json_file(p, validator=None)
    assert valid is True
    assert err is None


def test_validate_json_file_parse_error(tmp_path):
    p = tmp_path / "bad.json"
    # Write invalid JSON
    write_text(p, "{ not: valid, }")

    valid, err = nb.validate_json_file(p, validator=None)
    assert valid is False
    assert err is not None
    assert "JSON parse error" in err


def test_validate_mode_writes_csv(tmp_path):
    nbccs = tmp_path / "NBCCS"
    vault = tmp_path / "VAULT"
    nbccs.mkdir()
    vault.mkdir()

    # valid and invalid files
    good = {"case_id": "C1", "snapshot_time": "2025-07-29T12:00:00Z", "version": "1.0", "payload": {}}
    bad = {"snapshot_time": "2025-07-29T12:00:00Z", "version": "1.0", "payload": {}}

    write_json(nbccs / "valid.json", good)
    write_json(nbccs / "invalid.json", bad)

    # call validate-only mode
    nb.sync(nbccs_dir=nbccs, vault_root=vault, schema_validator=lambda p: None if p.get("case_id") else "missing case_id", mode="validate", dry_run=False, verbose=False)

    index = vault / "evidence_index.csv"
    assert index.exists(), "evidence_index.csv should be created in validate mode"

    rows = read_csv_rows(index)
    assert len(rows) == 2

    originals = {r["original_name"] for r in rows}
    assert "NBCCS/valid.json" in originals
    assert "NBCCS/invalid.json" in originals

    # find invalid row
    invalid_row = [r for r in rows if r["original_name"] == "NBCCS/invalid.json"][0]
    assert invalid_row["valid_json"] == "false"
    assert invalid_row["validation_errors"] != ""


def test_sync_copies_valid_and_logs(tmp_path):
    nbccs = tmp_path / "NBCCS"
    vault = tmp_path / "VAULT"
    nbccs.mkdir()
    vault.mkdir()

    # put file in subdir to check directory preservation
    sub = nbccs / "subdir"
    sub.mkdir(parents=True)
    obj = {"case_id": "C2", "snapshot_time": "2025-07-29T13:00:00Z", "version": "1.0", "payload": {}}
    write_json(sub / "copyme.json", obj)

    # perform sync (real copy + log)
    nb.sync(nbccs_dir=nbccs, vault_root=vault, schema_validator=None, mode="sync", dry_run=False, verbose=False)

    mirror = vault / "NBCCS_MIRROR"
    assert mirror.exists()

    # find copied file under mirror/subdir
    mirror_sub = mirror / "subdir"
    assert mirror_sub.exists()
    files = list(mirror_sub.glob("*copyme.json"))
    assert len(files) == 1
    stored_file = files[0]
    assert stored_file.exists()

    # CSV
    index = vault / "evidence_index.csv"
    assert index.exists()
    rows = read_csv_rows(index)
    assert len(rows) == 1
    row = rows[0]
    assert row["original_name"] == "NBCCS/subdir/copyme.json"
    assert row["stored_relpath"] != ""
    assert "NBCCS_MIRROR" in row["stored_relpath"]
    assert row["valid_json"] == "true"
    assert stored_file.name in row["stored_relpath"]


def test_sync_dry_run_no_files_no_log(tmp_path):
    nbccs = tmp_path / "NBCCS"
    vault = tmp_path / "VAULT"
    nbccs.mkdir()
    vault.mkdir()

    obj = {"case_id": "C3", "snapshot_time": "2025-07-29T14:00:00Z", "version": "1.0", "payload": {}}
    write_json(nbccs / "dryrun.json", obj)

    # dry-run: should not create CSV nor mirror files
    nb.sync(nbccs_dir=nbccs, vault_root=vault, schema_validator=None, mode="sync", dry_run=True, verbose=False)

    mirror = vault / "NBCCS_MIRROR"
    assert mirror.exists(), "mirror directory is created by sync, even in dry-run"
    files = list(mirror.rglob("dryrun.json"))
    assert len(files) == 0, "No actual files should be copied in dry-run"

    index = vault / "evidence_index.csv"
    assert not index.exists(), "dry-run should not write CSV rows for sync mode"


def test_sync_logs_invalid_in_sync_mode(tmp_path):
    nbccs = tmp_path / "NBCCS"
    vault = tmp_path / "VAULT"
    nbccs.mkdir()
    vault.mkdir()

    # invalid JSON content
    write_text(nbccs / "bad.json", "{ bad json }")

    # run sync (not dry-run)
    nb.sync(nbccs_dir=nbccs, vault_root=vault, schema_validator=None, mode="sync", dry_run=False, verbose=False)

    index = vault / "evidence_index.csv"
    assert index.exists()
    rows = read_csv_rows(index)
    assert len(rows) == 1
    r = rows[0]
    assert r["original_name"] == "NBCCS/bad.json"
    assert r["valid_json"] == "false"
    assert r["stored_relpath"] == ""
    assert r["validation_errors"] != ""
