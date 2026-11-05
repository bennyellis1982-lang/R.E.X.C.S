# REX Master Vault 333 Inventory and Cleanup Runbook

This runbook turns the Master Vault 333 cleanup plan into a repeatable, evidence-safe workflow. It is designed for local drives and synced cloud folders such as Google Drive Desktop, Drive File Stream, Dropbox, OneDrive, or an external archive drive.

## Safety Rules

- Do not delete source files during inventory.
- Do not store plaintext tokens, API keys, fax credentials, or connector secrets in the repository.
- Copy suspicious files into review folders first, then wait for human approval before any deletion.
- Preserve hashes, timestamps, original paths, destination paths, and reasons for every ghost-file tag.
- Treat generated AI output and original evidence as separate material.

## Standard Vault Structure

`tools/rex_master_vault_333.py` creates this build layout under the selected vault root:

```text
REX_MASTER_VAULT_333/
  BUILD_YYYY-MM-DD_YYYYMMDD_HHMM/
    00_FRONT_DOOR_START_HERE/
    01_RUNNING_CANDIDATES/
    02_REX_CLOUD_WIDGETS_HTML/
    03_REXCAT_CATALINA/
    04_SOURCE_CODE_FULL_COPY/
    05_CONFIG_ENV_SENSITIVE_REVIEW/
    06_LOGS_TERMINAL_NOTES/
    07_PLACEHOLDER_DEAD_REVIEW_NOT_DELETED/
    09_ZIPS/
    10_GHOST_REX_DELETE_REVIEW/
    11_DELETION_RECEIPTS/
```

## Inventory Local and Synced Cloud Roots

Run the utility with every root that may contain REX material. Example:

```bash
python3 tools/rex_master_vault_333.py \
  ~/Desktop \
  ~/Downloads \
  ~/Documents \
  ~/Library/CloudStorage \
  --vault-root /Volumes/OneTouch/REX_MASTER_VAULT_333 \
  --include-all-web \
  --zip
```

The `--include-all-web` flag also collects HTML, CSS, JavaScript, and JSX files even when the path does not include `rex`, which helps capture legacy widgets and frontend fragments.

## Generated Evidence Records

The tool writes these records into `00_FRONT_DOOR_START_HERE/`:

- `rex_master_vault_inventory.json`
- `rex_master_vault_inventory.csv`
- `rex_master_vault_duplicates.json`
- `actions.jsonl` when files are copied

Each inventory row includes source path, preserved relative path, destination path, bucket, size, modified timestamp, SHA-256 hash, ghost tag, and reason. Duplicate groups are reported by SHA-256 so the owner can compare identical files before cleanup.

## Ghost-File Review

Potential ghost files are copied into `10_GHOST_REX_DELETE_REVIEW/` and receive deletion-review receipts in `11_DELETION_RECEIPTS/`. Current tags are:

- `KEEP`: user or project material.
- `REVIEW_EMPTY_FILE`: zero-byte file; review before deletion.
- `REVIEW_GENERATED_ARTIFACT`: file appears inside a generated/cache/build directory.
- `SAFE_TO_DELETE_AFTER_ZIP`: known operating-system junk such as `.DS_Store`.

The utility does not delete any source files. A human owner must review receipts before removal.

## Connector and Secret Handling

Configuration files are staged under `05_CONFIG_ENV_SENSITIVE_REVIEW/` when detected. This folder is for audit review only. Rotate or redact exposed secrets before sharing the vault.

## Zip Packaging

When `--zip` is used, the utility creates a timestamped archive under `09_ZIPS/` and logs its SHA-256 hash in `actions.jsonl`.

## Dry Run

Use dry-run mode to test inventory behavior without copying files or creating a zip:

```bash
python3 tools/rex_master_vault_333.py . --vault-root /tmp/REX_MASTER_VAULT_333 --dry-run
```

## Hardened Brain-State Hydration and Breathing

The utility now self-hydrates each build by writing `rex_master_vault_brain_state.json` into `00_FRONT_DOOR_START_HERE/`. This state file records the vault schema version, watched intake roots, current breath status, file counts, immutability-risk counts, vault folders, and active immutability guards.

Each non-dry run also breathes into `actions.jsonl` with `breath_started` and `breath_completed` events. Every action-log entry includes a previous hash and an entry hash, creating a hash-chained audit trail for copied files, zip creation, and heartbeat-style run status.

Use hydration mode to create the folder tree and brain-state contract before scanning any user files:

```bash
python3 tools/rex_master_vault_333.py \
  --vault-root /Volumes/OneTouch/REX_MASTER_VAULT_333 \
  --hydrate-only
```

## Intake and Automation Risk Awareness

Inventory rows now include `immutability_risk` and `risk_flags`. The tool flags intakes that can threaten immutability or confuse custody, including:

- automation and workflow paths such as `.github/workflows`, `launchagents`, `automator`, `cron`, `n8n`, `zapier`, and script folders;
- volatile intake locations such as Desktop, Downloads, temp folders, and sync-provider folders;
- configuration and credential-looking filenames;
- generated/cache/build directories;
- zero-byte ghost candidates and OS junk.

Risk flags do not prove wrongdoing. They are review signals so REX can remain aware of the user's environment without deleting or mutating source material.
