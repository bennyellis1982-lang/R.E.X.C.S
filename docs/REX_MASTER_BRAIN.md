# REX Master Brain Engine Blueprint

Status: foundational design file  
Version: 0.1.0  
Purpose: define the always-on REX master brain layer for indexing, evidence awareness, connector governance, reporting, vault integrity, and cloud/local continuity.

## 1. Mission

The REX Master Brain is the beginning of the owner engine: a security-first orchestration layer that keeps a living index of every authorized file, vault, connector, report, server, token reference, and evidence workflow while protecting chain of custody and reducing user confusion about where things belong.

It must be able to run in cloud environments while remaining useful on older Microsoft Windows and Apple macOS computers through lightweight local agents, browser-based interfaces, and low-resource background indexing.

## 2. Non-Negotiable Principles

1. **No plaintext secrets:** API keys, server tokens, connector credentials, fax credentials, cloud keys, and AI access tokens are never written directly into this file or committed to source control.
2. **Evidence first:** every file touched by the system receives source metadata, timestamps, SHA-256 hashing, and chain-of-custody events.
3. **User clarity:** if a file is misplaced, duplicated, corrupted, renamed, or confusingly located, REX records the issue and proposes a safer canonical location.
4. **Human + AI review:** court-ready materials must be explainable to humans, reproducible by technical reviewers, and separable from AI-generated commentary.
5. **Tamper awareness:** the brain continuously watches for manipulation, corruption, breach indicators, missing files, unexpected permission changes, and connector drift.
6. **Least privilege:** connectors only receive the permissions needed for their assigned job.
7. **Portable continuity:** the system must degrade gracefully on old computers and reconnect when cloud services become available.

## 3. Master Brain Responsibilities

### 3.1 Living Index

The Master Brain maintains a self-updating index for all authorized storage locations:

- documents, PDFs, text files, notes, and court drafts;
- spreadsheets, CSV files, Excel workbooks, and tabular exports;
- images, audio, video, body-worn-camera media, DVDs, and mixed evidence dumps;
- HTML reports, JSON manifests, JSONL logs, database exports, and archives;
- connector inventories, server inventories, token references, and service health records.

Each index entry should include:

- canonical path;
- original observed path;
- file type and MIME guess;
- size in bytes;
- created, modified, and indexed timestamps;
- SHA-256 digest;
- optional perceptual hashes for media;
- source connector or local source;
- owner/custodian;
- evidence tag or case tag;
- confidentiality level;
- legal hold status;
- last verification result;
- placement recommendation.

### 3.2 Placement Guardian

REX should constantly watch for user confusion or file placement mistakes, including:

- evidence stored outside a vault;
- reports mixed with raw evidence;
- duplicate names with different hashes;
- same hash in multiple locations;
- files added without a manifest entry;
- generated AI material placed beside original evidence without labeling;
- tokens or credentials discovered in documents or logs.

When confusion is detected, REX creates a `placement_alert` event and recommends one of these actions:

- move to evidence vault;
- copy to working review folder;
- quarantine as suspicious;
- label as generated material;
- redact credentials;
- preserve in place and add a manifest pointer.

### 3.3 Connector and Server Awareness

The Master Brain stores connector metadata, not raw secrets. Secrets must live in environment variables, operating-system keychains, hardware vaults, cloud secret managers, or a dedicated encrypted vault.

Connector records should track:

- connector name;
- connector type;
- permission scope;
- token reference name;
- owner;
- server or endpoint;
- health status;
- last successful check;
- last failed check;
- allowed actions;
- breach response action.

Supported connector categories:

- REX AI endpoints;
- OpenAI-compatible AI services;
- cloud drives and object stores;
- Git repositories;
- databases;
- fax and secure messaging providers;
- email intake sources;
- speech-to-text and text-to-speech services;
- podcast/audio generation services;
- legal research sources;
- statistics and public-record sources;
- monitoring, logging, and security scanners.

### 3.4 Security and Breach Watch

The brain continuously evaluates:

- hash mismatches;
- missing expected files;
- unexpected new files in protected folders;
- sudden file-size changes;
- impossible timestamp order;
- suspicious permission changes;
- connector authentication failures;
- repeated failed access attempts;
- leaked token patterns;
- malformed evidence bundles;
- unauthorized report edits;
- corrupted indexes or manifests.

Breach levels:

| Level | Name | Meaning | Required Response |
| --- | --- | --- | --- |
| 0 | Clear | No active concern | Continue indexing |
| 1 | Confusion | Misplaced or ambiguous files | Alert and recommend placement |
| 2 | Integrity Drift | Hash, metadata, or manifest mismatch | Freeze affected item and re-verify |
| 3 | Credential Risk | Token, secret, or connector anomaly | Quarantine and rotate secret |
| 4 | Evidence Risk | Chain-of-custody or source conflict | Lock vault and generate incident report |
| 5 | Active Breach | Confirmed unauthorized access or tampering | Halt connector, seal logs, notify owner |

### 3.5 Vault Locking and SHA-256 Chain

Every protected vault must support:

- SHA-256 hashing of every file;
- append-only JSONL event logs;
- previous-entry hash chaining;
- optional HMAC signing;
- immutable export manifests;
- vault lock mode;
- emergency read-only mode;
- evidence bundle creation;
- verification reports.

Vault lock mode means no mutation is allowed except appending audit events. Any unlock requires governance approval and must be logged.

### 3.6 Court-Ready Document Generation

REX must distinguish original evidence, extracted facts, human notes, and AI-generated analysis. Court-ready exports should include:

- cover page;
- case or matter identifier;
- evidence inventory;
- chain-of-custody table;
- SHA-256 hash table;
- source timeline;
- issue summary;
- relevant laws, procedures, policies, or standards;
- statistics used and their sources;
- AI-assistance disclosure section;
- verification appendix;
- export manifest.

Every generated document should be reproducible from the index, manifests, and logs.

### 3.7 Reports, Fax, Voice, and Podcast Output

The Master Brain can prepare multiple output forms from the same verified evidence packet:

- security reports;
- court-ready PDFs or HTML records;
- spreadsheet summaries;
- fax-ready cover sheets and attachments;
- read-out-loud scripts;
- text-to-speech audio summaries;
- podcast-style briefings;
- executive summaries;
- technical appendices;
- incident response packets.

Fax and messaging providers must be connector-based. REX prepares outbound packets, validates the recipient, logs the action, and records delivery status.

### 3.8 Legal, Statistical, and Procedure Matching

For each evidence packet, REX can create a research queue that searches for:

- relevant statutes and regulations;
- court rules and filing procedures;
- agency policies;
- evidence handling standards;
- forensic best practices;
- public statistics;
- comparable timelines;
- procedural deadlines.

Research results must be stored as citations and summaries. REX must not present legal conclusions as attorney advice; it should label outputs as research support unless reviewed by qualified counsel.

## 4. Runtime Architecture

### 4.1 Cloud Brain

The cloud brain provides:

- central index database;
- connector health checks;
- encrypted secret references;
- job queue;
- report rendering;
- media transcription and synthesis jobs;
- audit log storage;
- owner dashboard;
- backup and restore.

### 4.2 Local Lightweight Agent

The local agent provides:

- file watching;
- hashing;
- offline manifests;
- low-resource indexing;
- upload queue when internet returns;
- local vault lock enforcement where possible;
- compatibility with older Windows and macOS computers.

### 4.3 Synchronization Rules

1. Local agents can create signed index events while offline.
2. Cloud brain reconciles events by timestamp, source, previous hash, and file digest.
3. Conflicts are never silently overwritten.
4. Suspected tampering creates an incident event.
5. Generated reports are versioned and tied to the evidence state used to create them.

## 5. Canonical Folder Model

Recommended root folders:

```text
MasterVault_333/
  evidence_raw/
  evidence_working/
  reports_court_ready/
  reports_security/
  exports_fax/
  audio_podcasts/
  connector_manifests/
  legal_research/
  statistics/
  quarantine/
  recalls/
  indexes/
  audit_logs/
```

Rules:

- `evidence_raw/` is original source material and should be read-only after intake.
- `evidence_working/` is for copies, transcriptions, OCR, and analysis.
- `reports_court_ready/` contains finalized exports with manifests.
- `quarantine/` contains suspicious, misplaced, or credential-bearing files.
- `audit_logs/` contains append-only JSONL logs.

## 6. Event Types

The Master Brain should use structured event names:

- `index_started`
- `file_observed`
- `file_hashed`
- `file_changed`
- `file_missing`
- `duplicate_detected`
- `placement_alert`
- `connector_checked`
- `connector_failed`
- `credential_risk_detected`
- `vault_locked`
- `vault_unlocked`
- `breach_level_changed`
- `research_queued`
- `report_generated`
- `fax_packet_prepared`
- `audio_generated`
- `podcast_generated`
- `court_bundle_exported`

## 7. Master Brain State Schema

```json
{
  "brain_id": "rex-master-brain-333",
  "schema_version": "0.1.0",
  "owner_engine": true,
  "mode": "watchdog",
  "breach_level": 0,
  "vault_locked": false,
  "index_status": "ready",
  "connectors": [],
  "vaults": [],
  "active_cases": [],
  "research_queues": [],
  "report_jobs": [],
  "last_heartbeat_utc": null
}
```

## 8. Implementation Backlog

### Phase 1: Foundation

- Create the master brain file and schema.
- Add local index writer.
- Add SHA-256 manifest generation.
- Add placement alert rules.
- Add connector manifest format without storing secrets.

### Phase 2: Watchdog

- Add file-system watchers.
- Add breach-level scoring.
- Add vault lock events.
- Add incident report templates.
- Add offline-to-cloud sync queue.

### Phase 3: Evidence Intelligence

- Add OCR and transcription queues.
- Add spreadsheet and document parsers.
- Add legal/statistical research queues.
- Add court-ready report generation.
- Add human/AI disclosure sections.

### Phase 4: Output Engine

- Add fax packet preparation.
- Add read-out-loud scripts.
- Add text-to-speech summaries.
- Add podcast briefing generation.
- Add dashboards for old and new computers.

### Phase 5: Hardened Operations

- Add HMAC signatures.
- Add encrypted vault integration.
- Add role-based approval gates.
- Add connector rotation procedures.
- Add independent verification exports.

## 9. Safety Boundaries

The Master Brain must not:

- secretly collect files outside approved roots;
- store raw passwords or tokens in repository files;
- alter original evidence without explicit logged authorization;
- claim legal advice without qualified human review;
- hide AI involvement in generated documents;
- silently delete, overwrite, or rewrite evidence;
- bypass operating-system security controls.

## 10. Activation Statement

REX Master Brain begins as a living blueprint and control contract. It watches for file movement, evidence drift, connector failures, breaches, user confusion, and report needs. It protects original evidence, builds verified indexes, prepares human-readable and AI-readable records, and creates the foundation for a cloud-capable owner engine that remains usable on older computers.
