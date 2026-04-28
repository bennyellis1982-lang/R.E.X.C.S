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
