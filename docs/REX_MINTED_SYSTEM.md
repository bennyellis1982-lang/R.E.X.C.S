# REX Six-Decimal Minted System

`tools/rex_minted_system.py` is an offline reference ledger for exact six-decimal accounting, explicitly authorized mint events, full-chain verification, and an internal investor-readiness package.

## What “six zeros” means

The system uses six digits after the decimal point:

- `1` is stored as `1,000,000` integer micro-units and displayed as `1.000000`.
- `0.000001` is the smallest representable amount.
- Existing money or valuation is **not multiplied by one million**.
- Floating-point numbers, scientific notation, commas, currency symbols, negative values, and inputs with more than six decimals are rejected.

This is precision and auditability, not value creation.

## Safety boundary

The utility does **not** create or operate:

- a blockchain or smart contract;
- a wallet, custody service, exchange, broker, payment rail, or transfer service;
- a token sale, public offer, prospectus, managed investment scheme, or security;
- a market valuation, price, return forecast, or statement of investor demand.

It is a local accounting prototype. Any transition to a live virtual-asset or fundraising system requires separate legal, compliance, tax, accounting, governance, custody, cybersecurity, and independent technical review.

## 1. Initialize a policy-pinned ledger

Choose the name, symbol, issuer label, and supply cap from approved source material. The command never overwrites an existing policy or ledger.

```bash
python3 tools/rex_minted_system.py init \
  --state-dir /secure/working/REX_MINTED_SYSTEM \
  --name "REX Minted Unit" \
  --symbol REXM \
  --issuer REX-OPERATOR \
  --max-supply 1000000.000000
```

This writes:

```text
REX_MINTED_SYSTEM/
  policy.json
  ledger.jsonl
  .rex-mint.lock
```

`policy.json` fixes the six-decimal precision and supply cap. `ledger.jsonl` begins with a genesis record tied to the policy hash.

## 2. Append an explicitly authorized mint event

Use opaque recipient and operator identifiers rather than names, emails, wallet secrets, or other personal data. Every mint needs a unique idempotency key and an authorization reference.

```bash
python3 tools/rex_minted_system.py mint \
  --state-dir /secure/working/REX_MINTED_SYSTEM \
  --amount 25.000000 \
  --recipient-id INV-001 \
  --idempotency-key MINT-2026-000001 \
  --authorization-ref BOARD-2026-001 \
  --authorized-by OPERATOR-001 \
  --reason "Approved offline allocation" \
  --authorize
```

Without `--authorize`, the mutation is blocked. Repeating the same idempotency key with the same payload returns the existing event; repeating it with different data fails. A mint that exceeds the configured cap also fails.

## 3. Verify from genesis to ledger head

```bash
python3 tools/rex_minted_system.py verify \
  --state-dir /secure/working/REX_MINTED_SYSTEM
```

Verification recomputes:

- the policy ID;
- every entry hash and previous-hash link;
- sequence continuity;
- the exact base-unit/micro-unit representation;
- uniqueness of idempotency keys;
- recipient allocations, total minted, and remaining supply;
- enforcement of the configured supply cap.

The SHA-256 chain is **tamper-evident, not magically immutable**. A party that can replace the whole local state could rewrite it. For stronger assurance, regularly anchor the verified ledger-head hash in an independently controlled, signed, timestamped record.

## 4. Generate the investor-readiness package

```bash
python3 tools/rex_minted_system.py investor-pack \
  --state-dir /secure/working/REX_MINTED_SYSTEM \
  --output-dir /secure/working/REX_INVESTOR_PACK_2026-08-02
```

The output folder contains:

- `REX_Minted_System_Investor_Readiness.html` — the first-read internal working draft;
- `allocation_register.csv` — opaque recipient allocations derived from the verified ledger;
- `supply_snapshot.json` — policy, supply totals, and source hashes;
- `source_log.json` — local source hashes and official regulatory references;
- `manifest.json` — artifact hierarchy, hashes, routing, and circulation posture.

The first-read package is deliberately marked **PREPARE ONLY — DO NOT LAUNCH OR SOLICIT**. Unknown issuer, rights, pricing, valuation, proceeds, demand, custody, legal, AML/CTF, tax, and accounting facts remain `NOT PROVIDED`, `NOT DETERMINED`, `NOT IMPLEMENTED`, or `NOT ASSESSED`.

## Australian pre-launch gates

Current official references checked on 2 August 2026:

- [ASIC: Digital assets — financial products and services](https://www.asic.gov.au/regulatory-resources/digital-transformation/digital-assets-financial-products-and-services/) — token rights and features matter more than the label; financial-product, managed-investment-scheme, licensing, disclosure, and misleading-or-deceptive-conduct analysis may apply.
- [AUSTRAC: Register as a remittance or virtual asset service provider](https://www.austrac.gov.au/new-austrac/register-us/register-us-remittance-or-virtual-asset-service-provider) — assess registration and AML/CTF obligations before providing covered virtual-asset services.
- [ATO: Keeping crypto records](https://www.ato.gov.au/individuals-and-families/investments-and-assets/crypto-asset-investments/keeping-crypto-records) — retain transaction, purpose, counterparty/address, AUD valuation, exchange, wallet, and cost records as applicable.

These links and the project’s facts must be refreshed before any external circulation or live launch. The repository does not claim legal or regulatory compliance.

## Run tests

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile tools/rex_minted_system.py
```
