# REXCS Continuity Engine — Operating Contract

> **REXCS — Continuity you can prove.**

REXCS is a survival-oriented continuity system for long-running, high-consequence work. It must become more reliable as evidence, code, decisions, failures, tests, and checkpoints accumulate.

## Core loop

**Capture → Verify → Remember → Reason → Act → Audit → Improve → Checkpoint**

The system does not depend on conversational memory as its source of truth.

- **MasterVault** preserves source artifacts and provenance.
- **Rolling Memory** stores structured operational state and source references.
- **Heartbeat** verifies continuity and detects drift.
- **Command Core** routes bounded work.
- **Human Approval Gate** controls consequential writes and external actions.
- **Sovereign** presents verified state to the operator.
- **Codex/GitHub** provide a development and execution adapter, not the memory authority.

## Non-negotiable states

Every capability or claim is marked as one of:

- `VERIFIED` — supported by an identified source or deterministic check.
- `IMPLEMENTED` — code exists.
- `TESTED` — implementation has passed an identified test.
- `EXPERIMENTAL` — runnable or investigatory, not production-trusted.
- `PROPOSED` — design only.

Never promote a state without evidence.

## Continuity heartbeat

On every authorised engineering cycle:

1. Recover the latest verified checkpoint.
2. Verify referenced source artifacts before accepting prior assertions as fact.
3. Compare repository, manifests, tests, workflows and product state with the checkpoint.
4. Identify unfinished work, duplication, stale assumptions, security weaknesses, missing tests and unproductised capability.
5. Preserve working functionality and historical state.
6. Separate deterministic operations from model judgment.
7. Make the smallest useful improvement that can be tested.
8. Record **WHY → SOURCE → CHANGE → TEST → RESULT → COMMERCIAL EFFECT → NEXT ACTION**.
9. Write a resumable checkpoint.

## Safety and integrity

- Never silently alter source evidence or historical records.
- Never describe proposed functionality as implemented.
- Hashes and provenance are deterministic, not model-generated assertions.
- Consequential writes and external actions require an explicit approval state.
- Secrets never belong in source control or model-visible logs.
- Automation receives the minimum permissions required.
- Recovery and audit paths must remain usable without an AI model.

## Commercial acceptance test

A qualifying REXCS build must be able to stop mid-project, restart without conversational context, and reconstruct:

1. what was verified;
2. what changed;
3. what was being built;
4. what remains unresolved;
5. the next authorised action; and
6. the provenance supporting that reconstruction.

If it cannot do that, continuity is not yet proven.
