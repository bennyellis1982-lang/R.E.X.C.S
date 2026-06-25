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

## Evidence and Protocol Docs
- `docs/TIMELINE_2025-07_TO_PRESENT.md` provides the REX Timeline Hunter month-by-month reconstruction and solicitor evidence-gap checklist.
- `docs/WORKFLOW_PROTOCOL_REGISTRY.md` maps repository workflows and defines the PPPE / EEEP / BBBB immutable protocol stack for evidence preservation and legal-readiness review.
