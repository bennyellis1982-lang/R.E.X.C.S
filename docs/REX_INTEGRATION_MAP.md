# REXCS Integration Map

Status: design/control record for the REXCS integration layer. This file does not claim that every named service is live-synchronised. Each source must be marked as connected, import-only, export-only, or planned based on verifiable capability.

## Core rule

REXCS may coordinate records from multiple services, but source provenance must remain intact. A message, file, AI output, repository artifact, or connector result keeps its original source identity. Cross-platform similarity is not proof of shared authorship, compromise, or autonomous synchronisation.

## Current source map

| Source / label | Intended REXCS role | Current handling |
|---|---|---|
| OpenAI / ChatGPT REX | reasoning, structured extraction, FAZZ/EEEP/PPPE workflow assistance | API-capable via backend `OPENAI_API_KEY`; secret must never be committed |
| Gmail / "Gmail Rex" | email evidence, solicitor/client communications, alerts, workflow inputs | connector-backed; "Gmail Rex" is a continuity label, not a separate autonomous agent |
| GitHub `bennyellis1982-lang/R.E.X.C.S` | primary application/workflow repository | connected repository |
| GitHub `bennyellis1982-lang/Rexcore` | integrity/core-state foundation | connected repository |
| GitHub `bennyellis1982-lang/REXARMERY` | private inventory/cyber-security build repository | connected private repository; keep separate provenance |
| Grok / xAI outputs | external AI comparison, imported reports and correspondence | no direct Grok connector confirmed; ingest only from preserved exports, emails, files, or a future explicitly configured API |
| Claude / Anthropic outputs | external AI comparison, imported reports and development material | no direct Claude connector confirmed; ingest only from preserved exports/files or a future explicitly configured API |
| Slack | collaboration, project messages, operational records | connector-capable; preserve channel/thread/message provenance |
| Notion | case hub, project documentation, workflow knowledge | connector-capable; historical AI assertions remain lower-trust until source-backed |
| Google Drive | primary document/case indexes and commercial working material | connector-capable |
| Dropbox | evidence mirror, preserved files, media and manifests | connector-capable; Dropbox metadata/search is not automatically source truth |
| Outlook | parallel email/account evidence stream | connector-capable where account/tool limitations permit |
| Vercel | future hosting/deployment | account/team detected; no REXCS Vercel project confirmed at integration-map creation |
| Figma / Product Design | future product UI/prototype layer | optional; not evidence storage |

## Integration contract

Every adapter should emit a normalised record containing at least:

- `source_system`
- `source_account_or_workspace`
- `source_object_id`
- `source_timestamp`
- `acquired_timestamp_utc`
- `media_or_record_type`
- `original_name_or_subject`
- `content_reference`
- `hash_sha256` only when original bytes were actually acquired
- `evidence_status`: `verified_observation`, `record_assertion`, `user_report`, `reasonable_inference`, `unverified_concern`, or `unknown`
- `mutation_status`
- `chain_of_custody_reference`
- `review_status`

## BBB / EEEP / PPPE / FAZZ control gates

These labels are governance/workflow controls. They do not themselves create technical security guarantees.

1. Preserve the source before transformation.
2. Never overwrite an original record with a summary or AI output.
3. Separate facts, source assertions, user reports, inferences, and unknowns.
4. Record connector/tool failures instead of filling gaps by assumption.
5. Require explicit approval for destructive operations.
6. Never expose API keys, OAuth tokens, session cookies, or private keys in repositories, logs, prompts, screenshots, or evidence bundles.
7. AI-generated status claims remain unverified until supported by primary evidence or system logs.

## Cross-AI rule

Outputs from ChatGPT, Grok, Claude, Gemini, or any other model must be stored as model-generated records with provider/date/context provenance. Agreement between several AIs is not independent corroboration of an external fact. Corroboration requires underlying records, logs, documents, witnesses, or other primary evidence.

## Commercial separation

Personal MASTER_VAULT_333 evidence and sensitive case records must not be used in investor demos, public repositories, product screenshots, or pilot datasets. Commercial demos should use synthetic or separately authorised data.

## Next implementation layer

- backend OpenAI gateway using environment-only credentials;
- source adapter registry for Gmail, Drive, Dropbox, Notion, Slack, Outlook and GitHub;
- import adapters for Grok/Claude exports until direct authorised APIs/connectors are configured;
- append-only audit event format compatible with BREX / Master Vault controls;
- sanitised commercial/demo profile separated from personal evidence profiles.
