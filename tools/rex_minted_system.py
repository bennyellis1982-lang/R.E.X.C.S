#!/usr/bin/env python3
"""Offline, tamper-evident six-decimal mint ledger for R.E.X.C.S.

This module deliberately does not create a blockchain, wallet, exchange,
security, or public offering.  It provides exact fixed-point accounting,
operator-gated mint events, a SHA-256 hash chain, verification, and an internal
investor-readiness pack whose unknown commercial and legal facts stay unknown.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import html
import json
import os
import re
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal, ROUND_DOWN
from pathlib import Path
from typing import Iterator

try:  # POSIX locking is available on the macOS/Linux systems this repo targets.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on non-POSIX systems.
    fcntl = None


SCHEMA_VERSION = "1.0"
DECIMALS = 6
SCALE = 10**DECIMALS
ZERO_HASH = "0" * 64
DEFAULT_STATE_DIR = "REX_MINTED_SYSTEM"
AMOUNT_RE = re.compile(r"^(0|[1-9][0-9]{0,17})(?:\.([0-9]{1,6}))?$")
SYMBOL_RE = re.compile(r"^[A-Z][A-Z0-9]{1,11}$")
OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")

REGULATORY_REFERENCES = (
    {
        "authority": "ASIC",
        "title": "Digital assets: Financial products and services",
        "url": (
            "https://www.asic.gov.au/regulatory-resources/digital-transformation/"
            "digital-assets-financial-products-and-services/"
        ),
        "purpose": "Crypto-asset rights, financial-product analysis, and offering communications",
        "checked_on": "2026-08-02",
    },
    {
        "authority": "AUSTRAC",
        "title": "Register as a remittance or virtual asset service provider",
        "url": (
            "https://www.austrac.gov.au/new-austrac/register-us/"
            "register-us-remittance-or-virtual-asset-service-provider"
        ),
        "purpose": "VASP registration and AML/CTF pre-launch assessment",
        "checked_on": "2026-08-02",
    },
    {
        "authority": "ATO",
        "title": "Keeping crypto records",
        "url": (
            "https://www.ato.gov.au/individuals-and-families/investments-and-assets/"
            "crypto-asset-investments/keeping-crypto-records"
        ),
        "purpose": "Transaction and valuation recordkeeping requirements",
        "checked_on": "2026-08-02",
    },
)


class MintedSystemError(RuntimeError):
    """Raised when an invariant or operator safety gate is violated."""


@dataclass(frozen=True)
class LedgerSummary:
    policy_id: str
    symbol: str
    decimals: int
    max_supply: str
    max_supply_micro: int
    total_minted: str
    total_minted_micro: int
    remaining_supply: str
    remaining_supply_micro: int
    mint_event_count: int
    recipient_count: int
    ledger_entry_count: int
    ledger_head: str
    allocations_micro: dict[str, int]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_amount(value: str, *, allow_zero: bool = False) -> int:
    """Parse a base-unit amount into exact integer micro-units.

    Scientific notation, grouping separators, currency symbols, negatives, and
    precision beyond six decimal places are rejected rather than rounded.
    """

    normalized = value.strip()
    match = AMOUNT_RE.fullmatch(normalized)
    if not match:
        raise MintedSystemError(
            f"invalid amount {value!r}; use an unsigned number with at most {DECIMALS} decimal places"
        )
    whole = int(match.group(1))
    fractional = (match.group(2) or "").ljust(DECIMALS, "0")
    micro = whole * SCALE + int(fractional or "0")
    if micro == 0 and not allow_zero:
        raise MintedSystemError("amount must be greater than 0.000000")
    return micro


def format_amount(micro: int) -> str:
    if not isinstance(micro, int) or isinstance(micro, bool) or micro < 0:
        raise MintedSystemError("micro-unit amount must be a non-negative integer")
    whole, fractional = divmod(micro, SCALE)
    return f"{whole}.{fractional:0{DECIMALS}d}"


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as file_obj:
            file_obj.write(content)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextmanager
def state_lock(state_dir: Path) -> Iterator[None]:
    """Serialize policy and ledger mutations within one state directory."""

    if fcntl is None:
        raise MintedSystemError("cross-process state locking requires a POSIX platform")
    state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / ".rex-mint.lock"
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def policy_hash(policy: dict[str, object]) -> str:
    material = {key: value for key, value in policy.items() if key != "policy_id"}
    return sha256_text(canonical_json(material))


def entry_hash(entry: dict[str, object]) -> str:
    material = {key: value for key, value in entry.items() if key != "entry_hash"}
    return sha256_text(canonical_json(material))


def policy_path(state_dir: Path) -> Path:
    return state_dir / "policy.json"


def ledger_path(state_dir: Path) -> Path:
    return state_dir / "ledger.jsonl"


def validate_opaque_id(value: str, label: str) -> str:
    if not OPAQUE_ID_RE.fullmatch(value):
        raise MintedSystemError(
            f"{label} must be an opaque 1-64 character identifier using letters, numbers, '.', '_', ':', or '-'"
        )
    return value


def validate_plain_text(value: str, label: str, *, minimum: int, maximum: int) -> str:
    normalized = value.strip()
    if not minimum <= len(normalized) <= maximum:
        raise MintedSystemError(f"{label} must contain {minimum}-{maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise MintedSystemError(f"{label} cannot contain control characters")
    return normalized


def load_policy(state_dir: Path) -> dict[str, object]:
    path = policy_path(state_dir)
    if not path.is_file():
        raise MintedSystemError(f"missing policy file: {path}")
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MintedSystemError(f"cannot read policy: {exc}") from exc
    if not isinstance(policy, dict):
        raise MintedSystemError("policy root must be a JSON object")
    if policy.get("schema_version") != SCHEMA_VERSION:
        raise MintedSystemError(f"unsupported policy schema: {policy.get('schema_version')!r}")
    if policy.get("decimals") != DECIMALS:
        raise MintedSystemError(f"policy decimals must remain fixed at {DECIMALS}")
    if policy.get("scale_micro_units") != SCALE:
        raise MintedSystemError(f"policy scale must remain fixed at {SCALE}")
    name = policy.get("name")
    symbol = policy.get("symbol")
    issuer = policy.get("issuer")
    if not isinstance(name, str):
        raise MintedSystemError("policy name is invalid")
    validate_plain_text(name, "policy name", minimum=1, maximum=100)
    if not isinstance(symbol, str) or not SYMBOL_RE.fullmatch(symbol):
        raise MintedSystemError("policy symbol is invalid")
    if not isinstance(issuer, str):
        raise MintedSystemError("policy issuer is invalid")
    validate_plain_text(issuer, "policy issuer", minimum=1, maximum=160)
    if policy.get("network_mode") != "OFFLINE_REFERENCE_LEDGER":
        raise MintedSystemError("policy network mode is invalid")
    if policy.get("classification_status") != "NOT_DETERMINED":
        raise MintedSystemError("policy classification cannot be asserted by this utility")
    stored_id = policy.get("policy_id")
    computed_id = policy_hash(policy)
    if not isinstance(stored_id, str) or not hmac.compare_digest(stored_id, computed_id):
        raise MintedSystemError("policy hash mismatch; policy may have been altered")
    max_supply = policy.get("max_supply")
    max_supply_micro = policy.get("max_supply_micro")
    if (
        not isinstance(max_supply, str)
        or not isinstance(max_supply_micro, int)
        or isinstance(max_supply_micro, bool)
    ):
        raise MintedSystemError("policy supply fields have invalid types")
    if parse_amount(max_supply) != max_supply_micro or format_amount(max_supply_micro) != max_supply:
        raise MintedSystemError("policy supply representations do not agree")
    return policy


def load_ledger(state_dir: Path) -> list[dict[str, object]]:
    path = ledger_path(state_dir)
    if not path.is_file():
        raise MintedSystemError(f"missing ledger file: {path}")
    entries: list[dict[str, object]] = []
    try:
        with path.open("r", encoding="utf-8") as file_obj:
            for line_number, line in enumerate(file_obj, start=1):
                if not line.strip():
                    raise MintedSystemError(f"blank ledger line at line {line_number}")
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise MintedSystemError(f"ledger line {line_number} is not a JSON object")
                entries.append(value)
    except json.JSONDecodeError as exc:
        raise MintedSystemError(f"invalid ledger JSON on line {exc.lineno}: {exc.msg}") from exc
    except OSError as exc:
        raise MintedSystemError(f"cannot read ledger: {exc}") from exc
    if not entries:
        raise MintedSystemError("ledger is empty; expected a genesis record")
    return entries


def verify_entries(
    policy: dict[str, object], entries: list[dict[str, object]]
) -> LedgerSummary:
    expected_previous = ZERO_HASH
    total_minted_micro = 0
    mint_event_count = 0
    allocations: dict[str, int] = {}
    idempotency_keys: set[str] = set()

    for index, entry in enumerate(entries, start=1):
        sequence = entry.get("sequence")
        if sequence != index:
            raise MintedSystemError(
                f"ledger sequence mismatch at position {index}: found {sequence!r}"
            )
        previous = entry.get("prev_hash")
        if not isinstance(previous, str) or not hmac.compare_digest(previous, expected_previous):
            raise MintedSystemError(f"ledger chain break at sequence {index}")
        stored_hash = entry.get("entry_hash")
        computed_hash = entry_hash(entry)
        if not isinstance(stored_hash, str) or not hmac.compare_digest(stored_hash, computed_hash):
            raise MintedSystemError(f"ledger hash mismatch at sequence {index}")
        if entry.get("schema_version") != SCHEMA_VERSION:
            raise MintedSystemError(f"ledger schema mismatch at sequence {index}")
        if entry.get("policy_id") != policy["policy_id"]:
            raise MintedSystemError(f"ledger policy mismatch at sequence {index}")
        timestamp = entry.get("ts_utc")
        if not isinstance(timestamp, str):
            raise MintedSystemError(f"missing UTC timestamp at sequence {index}")
        try:
            parsed_timestamp = datetime.fromisoformat(timestamp)
        except ValueError as exc:
            raise MintedSystemError(f"invalid timestamp at sequence {index}") from exc
        if parsed_timestamp.utcoffset() != timezone.utc.utcoffset(parsed_timestamp):
            raise MintedSystemError(f"timestamp is not UTC at sequence {index}")

        event = entry.get("event")
        if index == 1:
            if event != "GENESIS" or entry.get("policy_id") != policy["policy_id"]:
                raise MintedSystemError("first ledger entry is not the expected policy genesis record")
        elif event == "MINT":
            amount = entry.get("amount")
            amount_micro = entry.get("amount_micro")
            recipient_id = entry.get("recipient_id")
            idempotency_key = entry.get("idempotency_key")
            if (
                not isinstance(amount, str)
                or not isinstance(amount_micro, int)
                or isinstance(amount_micro, bool)
            ):
                raise MintedSystemError(f"invalid amount fields at sequence {index}")
            if parse_amount(amount) != amount_micro or format_amount(amount_micro) != amount:
                raise MintedSystemError(f"amount representations do not agree at sequence {index}")
            if not isinstance(recipient_id, str):
                raise MintedSystemError(f"missing recipient identifier at sequence {index}")
            validate_opaque_id(recipient_id, "recipient_id")
            if not isinstance(idempotency_key, str) or not IDEMPOTENCY_RE.fullmatch(idempotency_key):
                raise MintedSystemError(f"invalid idempotency key at sequence {index}")
            authorization_ref = entry.get("authorization_ref")
            authorized_by = entry.get("authorized_by")
            reason = entry.get("reason")
            if not isinstance(authorization_ref, str):
                raise MintedSystemError(f"missing authorization reference at sequence {index}")
            if not isinstance(authorized_by, str):
                raise MintedSystemError(f"missing authorizer identifier at sequence {index}")
            validate_opaque_id(authorization_ref, "authorization_ref")
            validate_opaque_id(authorized_by, "authorized_by")
            if not isinstance(reason, str):
                raise MintedSystemError(f"invalid mint reason at sequence {index}")
            validate_plain_text(reason, "mint reason", minimum=3, maximum=240)
            if idempotency_key in idempotency_keys:
                raise MintedSystemError(f"duplicate idempotency key at sequence {index}")
            idempotency_keys.add(idempotency_key)
            total_minted_micro += amount_micro
            allocations[recipient_id] = allocations.get(recipient_id, 0) + amount_micro
            mint_event_count += 1
        else:
            raise MintedSystemError(f"unsupported ledger event {event!r} at sequence {index}")
        expected_previous = stored_hash

    max_supply_micro = policy["max_supply_micro"]
    if not isinstance(max_supply_micro, int):  # Narrow the type for static readers.
        raise MintedSystemError("invalid max supply type")
    if total_minted_micro > max_supply_micro:
        raise MintedSystemError("ledger total exceeds the configured supply cap")
    remaining_micro = max_supply_micro - total_minted_micro
    return LedgerSummary(
        policy_id=str(policy["policy_id"]),
        symbol=str(policy["symbol"]),
        decimals=DECIMALS,
        max_supply=str(policy["max_supply"]),
        max_supply_micro=max_supply_micro,
        total_minted=format_amount(total_minted_micro),
        total_minted_micro=total_minted_micro,
        remaining_supply=format_amount(remaining_micro),
        remaining_supply_micro=remaining_micro,
        mint_event_count=mint_event_count,
        recipient_count=len(allocations),
        ledger_entry_count=len(entries),
        ledger_head=expected_previous,
        allocations_micro=dict(sorted(allocations.items())),
    )


def _verify_state_unlocked(
    state_dir: Path,
) -> tuple[dict[str, object], list[dict[str, object]], LedgerSummary]:
    policy = load_policy(state_dir)
    entries = load_ledger(state_dir)
    return policy, entries, verify_entries(policy, entries)


def verify_state(state_dir: Path) -> tuple[dict[str, object], list[dict[str, object]], LedgerSummary]:
    if not state_dir.is_dir():
        raise MintedSystemError(f"state directory does not exist: {state_dir}")
    with state_lock(state_dir):
        return _verify_state_unlocked(state_dir)


def init_state(
    state_dir: Path,
    *,
    name: str,
    symbol: str,
    issuer: str,
    max_supply: str,
) -> tuple[dict[str, object], LedgerSummary]:
    normalized_name = validate_plain_text(name, "name", minimum=1, maximum=100)
    normalized_symbol = symbol.strip().upper()
    if not SYMBOL_RE.fullmatch(normalized_symbol):
        raise MintedSystemError("symbol must contain 2-12 uppercase letters or numbers and start with a letter")
    normalized_issuer = validate_plain_text(issuer, "issuer", minimum=1, maximum=160)
    max_supply_micro = parse_amount(max_supply)

    with state_lock(state_dir):
        if policy_path(state_dir).exists() or ledger_path(state_dir).exists():
            raise MintedSystemError(
                f"state already exists under {state_dir}; initialization never overwrites it"
            )
        created_at = utc_now()
        policy: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "name": normalized_name,
            "symbol": normalized_symbol,
            "issuer": normalized_issuer,
            "decimals": DECIMALS,
            "scale_micro_units": SCALE,
            "max_supply": format_amount(max_supply_micro),
            "max_supply_micro": max_supply_micro,
            "network_mode": "OFFLINE_REFERENCE_LEDGER",
            "classification_status": "NOT_DETERMINED",
            "created_at_utc": created_at,
        }
        policy["policy_id"] = policy_hash(policy)
        genesis: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "sequence": 1,
            "ts_utc": created_at,
            "event": "GENESIS",
            "policy_id": policy["policy_id"],
            "prev_hash": ZERO_HASH,
        }
        genesis["entry_hash"] = entry_hash(genesis)
        atomic_write_text(policy_path(state_dir), json.dumps(policy, indent=2, ensure_ascii=False) + "\n")
        atomic_write_text(ledger_path(state_dir), canonical_json(genesis) + "\n")
        summary = verify_entries(policy, [genesis])
    return policy, summary


def append_mint(
    state_dir: Path,
    *,
    amount: str,
    recipient_id: str,
    idempotency_key: str,
    authorization_ref: str,
    authorized_by: str,
    reason: str,
    authorize: bool,
) -> tuple[dict[str, object], LedgerSummary, bool]:
    if not authorize:
        raise MintedSystemError("mint blocked: the operator must supply --authorize")
    amount_micro = parse_amount(amount)
    recipient_id = validate_opaque_id(recipient_id, "recipient_id")
    if not IDEMPOTENCY_RE.fullmatch(idempotency_key):
        raise MintedSystemError(
            "idempotency_key must contain 8-128 characters using letters, numbers, '.', '_', ':', or '-'"
        )
    authorization_ref = validate_opaque_id(authorization_ref, "authorization_ref")
    authorized_by = validate_opaque_id(authorized_by, "authorized_by")
    normalized_reason = validate_plain_text(reason, "reason", minimum=3, maximum=240)

    with state_lock(state_dir):
        policy, entries, summary = _verify_state_unlocked(state_dir)
        matching = [entry for entry in entries if entry.get("idempotency_key") == idempotency_key]
        if matching:
            existing = matching[0]
            expected = {
                "amount_micro": amount_micro,
                "recipient_id": recipient_id,
                "authorization_ref": authorization_ref,
                "authorized_by": authorized_by,
                "reason": normalized_reason,
            }
            if any(existing.get(key) != value for key, value in expected.items()):
                raise MintedSystemError(
                    "idempotency key already exists with a different mint payload"
                )
            return existing, summary, True
        if amount_micro > summary.remaining_supply_micro:
            raise MintedSystemError(
                f"mint would exceed cap: requested {format_amount(amount_micro)}, "
                f"remaining {summary.remaining_supply}"
            )

        event: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "sequence": len(entries) + 1,
            "ts_utc": utc_now(),
            "event": "MINT",
            "policy_id": policy["policy_id"],
            "amount": format_amount(amount_micro),
            "amount_micro": amount_micro,
            "recipient_id": recipient_id,
            "idempotency_key": idempotency_key,
            "authorization_ref": authorization_ref,
            "authorized_by": authorized_by,
            "reason": normalized_reason,
            "prev_hash": summary.ledger_head,
        }
        event["entry_hash"] = entry_hash(event)
        with ledger_path(state_dir).open("a", encoding="utf-8") as file_obj:
            file_obj.write(canonical_json(event) + "\n")
            file_obj.flush()
            os.fsync(file_obj.fileno())
        entries.append(event)
        new_summary = verify_entries(policy, entries)
    return event, new_summary, False


def allocation_percentage(amount_micro: int, max_supply_micro: int) -> str:
    percentage = (
        Decimal(amount_micro) * Decimal(100) / Decimal(max_supply_micro)
    ).quantize(Decimal("0.0001"), rounding=ROUND_DOWN)
    return f"{percentage:.4f}%"


def build_investor_pack(state_dir: Path, output_dir: Path) -> Path:
    if not state_dir.is_dir():
        raise MintedSystemError(f"state directory does not exist: {state_dir}")
    with state_lock(state_dir):
        policy, _entries, summary = _verify_state_unlocked(state_dir)
        ledger_digest = sha256_file(ledger_path(state_dir))
        policy_digest = sha256_file(policy_path(state_dir))
    if output_dir.exists():
        raise MintedSystemError(
            f"output directory already exists: {output_dir}; investor-pack generation never overwrites"
        )
    output_dir.mkdir(parents=True)
    generated_at = utc_now()
    title = f"{policy['name']} investor readiness pack"
    html_name = "REX_Minted_System_Investor_Readiness.html"
    html_path = output_dir / html_name
    allocation_path = output_dir / "allocation_register.csv"
    snapshot_path = output_dir / "supply_snapshot.json"
    source_log_path = output_dir / "source_log.json"

    with allocation_path.open("w", encoding="utf-8", newline="") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=["recipient_id", "allocated", "allocated_micro", "percent_of_cap"],
        )
        writer.writeheader()
        for recipient_id, micro in summary.allocations_micro.items():
            writer.writerow(
                {
                    "recipient_id": recipient_id,
                    "allocated": format_amount(micro),
                    "allocated_micro": micro,
                    "percent_of_cap": allocation_percentage(micro, summary.max_supply_micro),
                }
            )

    snapshot = {
        "generated_at_utc": generated_at,
        "source_posture": "verified_from_local_policy_and_hash_chained_ledger",
        "summary": asdict(summary),
        "policy": policy,
        "ledger_sha256": ledger_digest,
        "policy_file_sha256": policy_digest,
    }
    atomic_write_text(snapshot_path, json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n")
    source_log = {
        "generated_at_utc": generated_at,
        "local_sources": [
            {"source_label": "policy.json", "sha256": policy_digest},
            {"source_label": "ledger.jsonl", "sha256": ledger_digest},
        ],
        "absolute_source_paths_disclosed": False,
        "regulatory_references": list(REGULATORY_REFERENCES),
        "refresh_required_before_external_use": True,
    }
    atomic_write_text(source_log_path, json.dumps(source_log, indent=2, ensure_ascii=False) + "\n")

    allocation_rows = "".join(
        "<tr>"
        f"<td><code>{html.escape(recipient_id)}</code></td>"
        f"<td>{html.escape(format_amount(micro))} {html.escape(str(policy['symbol']))}</td>"
        f"<td>{html.escape(allocation_percentage(micro, summary.max_supply_micro))}</td>"
        "</tr>"
        for recipient_id, micro in summary.allocations_micro.items()
    )
    if not allocation_rows:
        allocation_rows = (
            '<tr><td colspan="3" class="muted">No mint allocations recorded.</td></tr>'
        )
    reference_rows = "".join(
        "<li>"
        f"<a href=\"{html.escape(ref['url'])}\">{html.escape(ref['authority'])}: "
        f"{html.escape(ref['title'])}</a> — {html.escape(ref['purpose'])} "
        f"(link checked {html.escape(ref['checked_on'])})"
        "</li>"
        for ref in REGULATORY_REFERENCES
    )

    rendered = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{ --ink:#14213d; --muted:#5d6678; --line:#d8dee9; --paper:#fff; --wash:#f4f7fb; --warn:#8a3b12; --accent:#145c9e; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--wash); color:var(--ink); font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
    main {{ max-width:1040px; margin:32px auto; background:var(--paper); padding:46px 54px; box-shadow:0 10px 35px #13213a18; }}
    h1 {{ font-size:34px; line-height:1.1; margin:12px 0; }} h2 {{ margin-top:34px; border-bottom:1px solid var(--line); padding-bottom:8px; }}
    .eyebrow {{ color:var(--accent); font-weight:750; letter-spacing:.08em; text-transform:uppercase; }}
    .warning {{ background:#fff4ea; border-left:5px solid #d56a1f; padding:16px 18px; margin:20px 0; color:var(--warn); }}
    .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:24px 0; }}
    .card {{ border:1px solid var(--line); border-radius:8px; padding:14px; }} .card b {{ display:block; font-size:20px; }}
    .muted, small {{ color:var(--muted); }} table {{ border-collapse:collapse; width:100%; }} th,td {{ border-bottom:1px solid var(--line); padding:10px 8px; text-align:left; }}
    th {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }} td, code {{ overflow-wrap:anywhere; }}
    .status {{ display:inline-block; border:1px solid var(--line); border-radius:999px; padding:4px 10px; font-weight:700; }}
    .approval {{ margin-top:44px; display:grid; grid-template-columns:1fr 1fr; gap:32px; }} .approval > div {{ min-width:0; }} .dots {{ max-width:100%; letter-spacing:2px; color:#697386; white-space:nowrap; overflow:hidden; }}
    a {{ overflow-wrap:anywhere; }}
    code {{ font-family:"SFMono-Regular",Consolas,monospace; font-size:.92em; }}
    @media (max-width:760px) {{ main {{ margin:0; padding:28px 22px; }} .cards {{ grid-template-columns:1fr 1fr; }} .approval {{ grid-template-columns:1fr; }} }}
    @media print {{ body {{ background:#fff; }} main {{ margin:0; max-width:none; box-shadow:none; }} a {{ color:inherit; }} }}
  </style>
</head>
<body><main>
  <div class="eyebrow">Internal working draft · not an offer · generated {html.escape(generated_at)}</div>
  <h1>{html.escape(title)}</h1>
  <p><span class="status">Decision: PREPARE ONLY — DO NOT LAUNCH OR SOLICIT</span></p>
  <div class="warning"><strong>No valuation has been multiplied and no investor demand has been asserted.</strong> Six decimals means accounting precision: one unit is displayed as <code>1.000000</code>. This offline ledger is not a blockchain, wallet, exchange, security, prospectus, or invitation to invest.</div>

  <div class="cards">
    <div class="card"><small>Precision</small><b>{DECIMALS} decimals</b><span class="muted">1 unit = {SCALE:,} micro-units</span></div>
    <div class="card"><small>Supply cap</small><b>{html.escape(summary.max_supply)}</b><span class="muted">{html.escape(summary.symbol)}</span></div>
    <div class="card"><small>Total minted</small><b>{html.escape(summary.total_minted)}</b><span class="muted">verified from ledger</span></div>
    <div class="card"><small>Remaining</small><b>{html.escape(summary.remaining_supply)}</b><span class="muted">under configured cap</span></div>
  </div>

  <h2>Verified system facts</h2>
  <table><tbody>
    <tr><th>Issuer label</th><td>{html.escape(str(policy['issuer']))}</td></tr>
    <tr><th>System</th><td>{html.escape(str(policy['name']))} ({html.escape(str(policy['symbol']))})</td></tr>
    <tr><th>Mode</th><td>Offline reference ledger; no custody or transfer rail</td></tr>
    <tr><th>Policy ID</th><td><code>{html.escape(summary.policy_id)}</code></td></tr>
    <tr><th>Ledger head</th><td><code>{html.escape(summary.ledger_head)}</code></td></tr>
    <tr><th>Mint events</th><td>{summary.mint_event_count}</td></tr>
  </tbody></table>

  <h2>Allocation register</h2>
  <p class="muted">Opaque recipient identifiers only. This is an accounting allocation register, not evidence of payment, ownership rights, wallet delivery, or investor acceptance.</p>
  <table><thead><tr><th>Recipient ID</th><th>Allocated</th><th>Percent of cap</th></tr></thead><tbody>{allocation_rows}</tbody></table>

  <h2>Decision-critical facts not provided</h2>
  <table><thead><tr><th>Item</th><th>Status</th><th>Required before external use</th></tr></thead><tbody>
    <tr><td>Legal issuer entity and authority</td><td>NOT PROVIDED</td><td>Corporate approvals and counsel confirmation</td></tr>
    <tr><td>Rights attached to a unit</td><td>NOT DETERMINED</td><td>Rights, transferability, redemption, governance, and financial-product analysis</td></tr>
    <tr><td>Valuation, price, proceeds, and use of funds</td><td>NOT PROVIDED</td><td>Source-backed financing case and deterministic tie-out</td></tr>
    <tr><td>Investor demand or book feedback</td><td>NOT PROVIDED</td><td>No demand claim without documented, authorized feedback</td></tr>
    <tr><td>Custody, wallet, chain, smart contract, and security audit</td><td>NOT IMPLEMENTED</td><td>Independent technical design and audit if a live system is approved</td></tr>
    <tr><td>AML/CTF, sanctions, KYC, privacy, tax, and accounting</td><td>NOT ASSESSED</td><td>Qualified Australian legal, compliance, tax, and accounting review</td></tr>
  </tbody></table>

  <h2>Investor strategy posture</h2>
  <p><strong>Targeting is intentionally disabled.</strong> There is not enough verified information to rank anchors, core buyers, price-sensitive accounts, or education targets. Define the security, issuer, capital need, use of proceeds, legal pathway, valuation framework, and authorized disclosure perimeter first. Investor outreach should be reviewed by counsel/compliance before use.</p>

  <h2>Pre-launch control gates</h2>
  <ol>
    <li>Counsel determines the rights and features of the proposed unit and whether it is, or involves, a financial product or managed investment scheme.</li>
    <li>All offer, investor-education, sounding, and public language is reviewed for Australian disclosure and misleading-or-deceptive-conduct risk.</li>
    <li>The operating model is assessed against AUSTRAC virtual-asset service obligations before any exchange, transfer, custody, brokerage, or sale service begins.</li>
    <li>Corporate authorization, beneficial ownership, AML/CTF program, KYC, sanctions, privacy, tax, accounting, custody, cybersecurity, incident response, and external audit controls are evidenced.</li>
    <li>The supply cap, allocations, valuation, price, proceeds, dilution/economic rights, and use of funds are independently tied out.</li>
    <li>A fallback plan is approved: remain an offline accounting prototype if any gate is incomplete.</li>
  </ol>

  <h2>Current official references</h2>
  <ul>{reference_rows}</ul>
  <p class="muted">Links are time-sensitive and must be refreshed before launch or external circulation. This working pack is not legal, tax, accounting, investment, or financial-product advice.</p>

  <div class="approval">
    <div><strong>Operator approval</strong><div class="dots">................................................................................</div><small>Name / role / date</small></div>
    <div><strong>Legal &amp; compliance gate</strong><div class="dots">................................................................................</div><small>Counsel / compliance / date</small></div>
  </div>
</main></body></html>
"""
    atomic_write_text(html_path, rendered)

    manifest = {
        "name": "REX minted system investor readiness package",
        "created_at": generated_at,
        "status": "working_draft",
        "first_read": {
            "path": html_name,
            "format": "html",
            "purpose": "Internal prepare-only investor and issuance readiness view",
            "sha256": sha256_file(html_path),
        },
        "companion_deliverables": [],
        "support_artifacts": [
            {"path": allocation_path.name, "role": "allocation register", "sha256": sha256_file(allocation_path)},
            {"path": snapshot_path.name, "role": "verified supply snapshot", "sha256": sha256_file(snapshot_path)},
            {"path": source_log_path.name, "role": "source and reference log", "sha256": sha256_file(source_log_path)},
        ],
        "agent_artifacts": [],
        "transaction_workflow": "digital-asset issuance readiness",
        "lead_skill": "capital-markets-issuance",
        "supporting_skills": [],
        "routing_confidence": "medium",
        "handoff_contracts_used": [],
        "routing_reason": "User requested an investor package for a six-decimal minted system",
        "circulation_posture": "internal_working_draft_not_an_offer",
    }
    atomic_write_text(output_dir / "manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    return html_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Operate an offline, fixed six-decimal, tamper-evident REX mint ledger."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a new policy and genesis ledger")
    init_parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    init_parser.add_argument("--name", required=True)
    init_parser.add_argument("--symbol", required=True)
    init_parser.add_argument("--issuer", required=True)
    init_parser.add_argument("--max-supply", required=True)

    mint_parser = subparsers.add_parser("mint", help="Append one explicitly authorized mint event")
    mint_parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    mint_parser.add_argument("--amount", required=True)
    mint_parser.add_argument("--recipient-id", required=True)
    mint_parser.add_argument("--idempotency-key", required=True)
    mint_parser.add_argument("--authorization-ref", required=True)
    mint_parser.add_argument("--authorized-by", required=True)
    mint_parser.add_argument("--reason", required=True)
    mint_parser.add_argument(
        "--authorize",
        action="store_true",
        help="Confirm this offline ledger mutation is explicitly approved",
    )

    verify_parser = subparsers.add_parser("verify", help="Read and verify the policy and full hash chain")
    verify_parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    verify_parser.add_argument("--json", action="store_true", help="Print the summary as JSON")

    pack_parser = subparsers.add_parser(
        "investor-pack", help="Generate an internal prepare-only investor readiness package"
    )
    pack_parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    pack_parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        state_dir = Path(args.state_dir).expanduser()
        if args.command == "init":
            policy, summary = init_state(
                state_dir,
                name=args.name,
                symbol=args.symbol,
                issuer=args.issuer,
                max_supply=args.max_supply,
            )
            print("REX minted system initialized")
            print(f"- State: {state_dir.resolve()}")
            print(f"- Policy ID: {policy['policy_id']}")
            print(f"- Precision: {DECIMALS} decimals ({SCALE:,} micro-units per unit)")
            print(f"- Supply cap: {summary.max_supply} {summary.symbol}")
            print("- Live blockchain/wallet/exchange created: no")
        elif args.command == "mint":
            event, summary, replayed = append_mint(
                state_dir,
                amount=args.amount,
                recipient_id=args.recipient_id,
                idempotency_key=args.idempotency_key,
                authorization_ref=args.authorization_ref,
                authorized_by=args.authorized_by,
                reason=args.reason,
                authorize=args.authorize,
            )
            print("REX mint event verified" if replayed else "REX mint event appended")
            print(f"- Sequence: {event['sequence']}")
            print(f"- Amount: {event['amount']} {summary.symbol}")
            print(f"- Total minted: {summary.total_minted} {summary.symbol}")
            print(f"- Remaining under cap: {summary.remaining_supply} {summary.symbol}")
            print(f"- Idempotent replay: {'yes' if replayed else 'no'}")
        elif args.command == "verify":
            _policy, _entries, summary = verify_state(state_dir)
            if args.json:
                print(json.dumps(asdict(summary), indent=2, ensure_ascii=False))
            else:
                print("REX minted system verification: PASS")
                print(f"- Ledger entries: {summary.ledger_entry_count}")
                print(f"- Mint events: {summary.mint_event_count}")
                print(f"- Total minted: {summary.total_minted} {summary.symbol}")
                print(f"- Remaining: {summary.remaining_supply} {summary.symbol}")
                print(f"- Ledger head: {summary.ledger_head}")
        elif args.command == "investor-pack":
            first_read = build_investor_pack(state_dir, Path(args.output_dir).expanduser())
            print("REX investor readiness package generated")
            print(f"- First read: {first_read.resolve()}")
            print("- Circulation posture: internal working draft; not an offer")
        else:  # pragma: no cover - argparse enforces valid commands.
            parser.error(f"unknown command: {args.command}")
    except MintedSystemError as exc:
        parser.exit(2, f"error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
