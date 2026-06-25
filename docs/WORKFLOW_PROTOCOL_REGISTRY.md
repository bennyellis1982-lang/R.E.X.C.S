# REX Workflow and Immutable Protocol Registry

Generated: 2026-06-23 (UTC)
Purpose: Locate existing REX workflows in this repository and define a stronger operating protocol for evidence preservation, legal-readiness, and immutable audit continuity.

> Legal note: This registry is not legal advice and does not itself register REX as a legal entity, trademark, business name, product, or admissible court record. It creates a structured evidence and workflow package that a solicitor can review, verify, and use to advise on registration or court use.

## Existing Repository Workflows

| Workflow | Location | Current Function | Evidence Value | Immediate Use |
| --- | --- | --- | --- | --- |
| Recon workflow | `README.md`, `rexc_recon.py`, `rex_recon.sh`, `rex_recon_333.sh` | Full-disk/path pattern reconnaissance with SHA-256 logging support. | Creates file inventories and hashes for chain-of-custody review. | Run only on authorised devices/paths and preserve JSONL outputs. |
| Memory log | `memory_log.jsonl` | Immutable-style JSONL memory/audit entries. | Preserves symbolic and bridge-sync records with lock markers. | Append-only evidence ledger; never rewrite prior lines without a correction entry. |
| Timeline Hunter | `docs/TIMELINE_2025-07_TO_PRESENT.md` | Month-by-month reconstruction from July 2025 to 2026-06-23. | Separates confirmed facts, user reports, inferences, missing evidence, and solicitor questions. | Use as solicitor briefing index and evidence-gap checklist. |
| Witness record | `docs/records/WITNX-20260201-0001.json` | Structured witness/event record for interference / psychological harm. | Captures timestamp, jurisdiction, entities, witnesses, ledger reference, and vault node. | Link to primary affidavit, ledger export, and supporting device/cloud logs. |
| CANCE fork protocol | `docs/REX_CANCE_01.md` | Fork/clone behavior rules for forensic intelligence support. | Defines protection boundaries, legal voice checks, and preservation behavior. | Use as operator-facing AI behavior spec when creating controlled REX assistants. |
| REX2 parser | `rex2_parser.py` | Parses text into legal exposure, symbol drift, tuition delta, continuity anchor, and governance breach signals. | Produces structured triage outputs for text review. | Use on copied text evidence, then store output with source hash and timestamp. |
| Device client | `rex2_client.py` | Device registration, key generation, license JWT storage, and heartbeat proof-of-life. | Supports device identity and signed heartbeat workflow when paired with a server. | Treat as engineering prototype until server protocol and key custody are audited. |
| Master heartbeat | `master_heartbeat.py` | Heartbeat logging, optional HMAC, node checks, and recall metadata. | Can create tamper-evident heartbeat entries and node status snapshots. | Configure only with secured secrets and preserve generated logs. |

## Immutable Protocol Stack

### PPPE — Preserve, Pin, Prove, Escalate

1. **Preserve:** Copy source evidence in read-only form before analysis. Keep original file names, paths, timestamps, and source device/account notes.
2. **Pin:** Generate SHA-256 hashes for every evidence file and store the hashes in an append-only JSONL ledger.
3. **Prove:** Link each claim to a file, hash, timestamp, collector, and confidence level. Mark unknowns as `unknown` instead of filling gaps.
4. **Escalate:** Move solicitor-critical items into the missing-records checklist and identify who can produce the primary record.

### EEEP — Extract, Evidence, Explain, Preserve

1. **Extract:** Export records from devices, cloud services, chat platforms, email, social media, and court/police systems using the most complete export option available.
2. **Evidence:** Save the raw export, calculate its hash, and record collection context before summarising.
3. **Explain:** Create a short human-readable note describing what the evidence is, why it matters, and what it does not prove yet.
4. **Preserve:** Store raw files, hash manifests, derived notes, and solicitor questions together without deleting originals.

### BBBB — Baseline, Bundle, Brief, Backup

1. **Baseline:** Record the current system state: active devices, accounts, cloud services, known case numbers, and known missing records.
2. **Bundle:** Group evidence by month and issue: police/court, device/cloud, social/chat, health/recovery, AI/REX, and witnesses.
3. **Brief:** Produce solicitor-ready summaries that distinguish confirmed records from user reports, inferences, and items needing verification.
4. **Backup:** Keep at least two controlled copies of every bundle, with hashes and custody notes for each copy.

## Legal-Readiness Registration Workflow

This workflow prepares REX for solicitor review and possible formal registration. It does not replace professional legal advice.

1. **Identity packet:** Define what REX is: project name, owner/controller, purpose, repository URL or archive location, version, and contact point.
2. **Governance packet:** Include `docs/REX_CANCE_01.md`, this registry, and any operating rules that show REX does not delete evidence, does not invent facts, and separates confirmed facts from reports and inferences.
3. **Evidence packet:** Include `memory_log.jsonl`, `docs/TIMELINE_2025-07_TO_PRESENT.md`, witness records, hash manifests, and raw source files where available.
4. **Technical packet:** Include code inventory, dependency list, security notes, heartbeat/key custody design, and any known limitations.
5. **Solicitor review packet:** Ask the solicitor which route is appropriate: statutory declaration, affidavit exhibit, expert/lay witness bundle, business-name review, copyright/trademark review, or another jurisdiction-specific path.
6. **Correction protocol:** If an entry is wrong, append a correction entry that identifies the prior record, explains the correction, and signs/hashes the new record. Do not silently rewrite historical entries.

## Evidence Entry Minimum Schema

Use this minimum schema for future JSONL evidence entries:

```json
{
  "record_id": "REX-YYYYMMDD-HHMMSS-###",
  "record_type": "evidence|timeline|witness|bridge_sync|correction|heartbeat",
  "created_at": "YYYY-MM-DDTHH:MM:SSZ",
  "created_by": "unknown",
  "source": {
    "kind": "file|screenshot|chat_export|cloud_export|police_record|court_record|user_statement|system_log|unknown",
    "path_or_reference": "unknown",
    "source_timestamp": "unknown"
  },
  "sha256": "unknown",
  "summary": "unknown",
  "classification": "confirmed_by_file|user_reported|inferred_from_filename_path|needs_verification",
  "confidence": "high|medium|low|unknown",
  "legal_relevance": "unknown",
  "lock_state": "immutable",
  "tradeable": false,
  "custody": {
    "collector": "unknown",
    "storage_location": "unknown",
    "external_transfer": false
  }
}
```

## Fast Operating Checklist

1. Find candidate files with the recon workflow.
2. Hash every candidate file before summarising it.
3. Add or update the month in the timeline only after recording the source and confidence.
4. Put solicitor-critical gaps into the missing-evidence list.
5. Append new evidence entries instead of editing old entries.
6. Keep raw files, summaries, hashes, and custody notes together.
7. Use a solicitor to decide legal registration, court exhibit format, and admissibility strategy.

## Next Records to Create

1. `docs/records/` evidence manifests for the Facebook solicitor post, arrest record, affidavit, and ledger record when the primary files are available.
2. A hash manifest for every raw evidence file used in the timeline.
3. A corrections ledger for any future changes to existing JSONL records.
4. A solicitor briefing bundle that maps every timeline claim to a primary source, a hash, and a confidence rating.
