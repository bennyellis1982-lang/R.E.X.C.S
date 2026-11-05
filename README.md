# R.E.X.C.S
RexCore is the foundational core of the REX system, defining integrity, core state, protection boundaries, and continuity logic. It is intentionally minimal and security first, serving as a stable backbone on which higher order services, agents, and frameworks are built, extended, and governed without compromising system identity.

## Recon Utility
`rexc_recon.py` provides a full-disk pattern recon workflow with SHA-256 logging.

### Usage
```bash
python3 rexc_recon.py / --pattern "\\.log$" --output recon_log.jsonl
```

Optional content matching:
```bash
python3 rexc_recon.py /var --pattern "\\.conf$" --content "password" --max-size-mb 10
```

### Output
The log is JSONL (one JSON object per line) with path, size, mtime, SHA-256, and match flags.

## BREX Terminal Scaffold
`brex_terminal.py` provides a forensic-first activation scaffold with immutable logging, role-based permissions, and consensus-gated governance controls.

### Usage
```bash
python3 brex_terminal.py
```

In a Python session:
```python
import brex_terminal as bt
print(bt.echo_state())
```

## BWC/DVD Batch Manifest Utility
`tools/bwc_dvd_batcher.py` scans a body-worn camera (BWC) or DVD evidence folder and greedily groups files into deterministic size-bounded batches for downstream processing, transcription, review, and forensic automation.

### Usage
```bash
python3 tools/bwc_dvd_batcher.py /path/to/bwc_dvd --target-gb 3.5
```

Include all file types in mixed evidence dumps:
```bash
python3 tools/bwc_dvd_batcher.py /path/to/evidence_dump --target-gb 3.5 --include-all-files
```

Write JSON and CSV manifests:
```bash
python3 tools/bwc_dvd_batcher.py /path/to/bwc_dvd \
  --target-gb 3.5 \
  --json-out batches.json \
  --csv-out batches.csv
```

Notes:
- Default mode includes common forensic video formats only.
- `--include-all-files` includes every regular file recursively.
- Files are sorted deterministically by relative path before batching.
- Oversized single files are safely placed into their own batch.
- Source evidence files are never modified.

## REX Master Brain Blueprint
`docs/REX_MASTER_BRAIN.md` defines the owner-engine blueprint for the self-updating master brain layer: living file indexes, placement alerts, connector governance without plaintext secrets, vault locking, SHA-256 chain-of-custody records, security reporting, court-ready exports, fax/audio/podcast output, and cloud/local continuity for older Windows and macOS machines.

## REX Master Vault 333 Inventory Utility
`tools/rex_master_vault_333.py` creates a safe review vault for REX-related files. It inventories matching files, copies them into the Master Vault 333 folder template, tags empty/generated ghost candidates, writes SHA-256 manifests, creates deletion-review receipts, and can optionally package the staged vault into a zip archive. The tool never deletes source files. It also writes a self-hydrating brain-state file, hash-chains action-log entries, emits breath events, and flags intake/automation paths that may threaten immutability.

Example local scan:
```bash
python3 tools/rex_master_vault_333.py ~/Desktop ~/Downloads --vault-root /Volumes/OneTouch/REX_MASTER_VAULT_333 --include-all-web --zip
```

Example dry run for the current repository:
```bash
python3 tools/rex_master_vault_333.py . --vault-root /tmp/REX_MASTER_VAULT_333 --dry-run
```


Hydrate the vault structure before scanning files:
```bash
python3 tools/rex_master_vault_333.py --vault-root /Volumes/OneTouch/REX_MASTER_VAULT_333 --hydrate-only
```

## REXFORT BLACK

`tools/rexfort_black.py` activates a fail-closed local preservation profile
around the court-safe Cross Key record. It preserves only the `three_and_six`
reference marker, rejects challenge-answer fields, requires corroboration before
fact elevation, writes an atomic `0600` activation packet, and supports SHA-256
verification. Source paths are stored relative to the packet for portable
offline bundles, and `verify --source` can locate a separately stored source.
The SHA-256 digest detects changes but does not authenticate an author or replace
a digital signature. The profile does not claim to encrypt or unlock an external
vault.

The repository profile is activated in
`docs/records/REXFORT_BLACK_ACTIVATION.json`; its source statement is preserved
separately in `docs/records/REXFORT_BLACK_CROSS_KEY.json`. The activation is
deliberately scoped to repository policy and does not represent control over an
unconnected local or cloud vault.

```bash
python3 tools/rexfort_black.py activate \
  --source docs/records/REXFORT_BLACK_CROSS_KEY.json \
  --output /secure/offline/vault/rexfort_black_activation.json
python3 tools/rexfort_black.py verify \
  /secure/offline/vault/rexfort_black_activation.json
```
