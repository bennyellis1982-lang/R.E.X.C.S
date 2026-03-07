#!/usr/bin/env python3
"""BREX Terminal Activation Scaffold v1.1 (forensic-first)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, List, Optional, Set, Tuple


# -------------------------
# 1) Ingress Control
# -------------------------
INGRESS = {
    "source": "Phoenix Hotel 343",
    "trust_level": "quarantined",  # quarantined | trusted
    "verify_hashes": True,
    "mutation": "forbidden",  # forbidden | allowed (only via gated override)
}

# -------------------------
# 2) Triple-AI Authority Chain
# -------------------------
AI_ROLES = {
    "REX": {
        "role": "Execution",
        "permission": {"trigger", "log", "cache"},
        "limits": {"cannot_assert_narrative"},
    },
    "POTTS": {
        "role": "Explanation",
        "permission": {"explain", "sanitize", "audit"},
        "limits": {"cannot_invoke_actions"},
    },
    "ADMIN": {
        "role": "Governance",
        "permission": {"bundle_control", "release_scope", "manual_overrides"},
        "limits": {"requires_consensus_for_elevation"},
    },
    "FAZZ": {
        "role": "Security Moderator",
        "permission": {"halt", "quarantine", "drift_detect"},
        "limits": {"non_interventionist_unless_breach"},
    },
}

# -------------------------
# 3) Local Terminal Modes
# -------------------------
MODES = ["cold_log", "watchdog", "live_echo", "quarantine_replay"]

# -------------------------
# 4) UX Signaling
# -------------------------
SIGNALS = {
    "✅": "Trustable state",
    "⚠️": "Flagged by FAZZ",
    "🔒": "Immutable snapshot",
    "🪞": "Live mirror node echo",
    "📦": "Exit bundle queued",
}


# -------------------------
# Core data structures
# -------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def hash_str(s: str) -> str:
    return sha256(s.encode("utf-8")).hexdigest()


@dataclass
class LogEntry:
    ts_utc: str
    actor: str
    action: str
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str = ""

    def seal(self) -> "LogEntry":
        blob = f"{self.ts_utc}|{self.actor}|{self.action}|{self.payload}|{self.prev_hash}"
        self.entry_hash = hash_str(blob)
        return self


@dataclass
class ImmutableLog:
    chain: List[LogEntry] = field(default_factory=list)

    def append(self, actor: str, action: str, payload: Dict[str, Any]) -> LogEntry:
        prev = self.chain[-1].entry_hash if self.chain else "GENESIS"
        entry = LogEntry(
            ts_utc=utc_now_iso(),
            actor=actor,
            action=action,
            payload=payload,
            prev_hash=prev,
        ).seal()
        self.chain.append(entry)
        return entry

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        prev = "GENESIS"
        for i, entry in enumerate(self.chain):
            blob = (
                f"{entry.ts_utc}|{entry.actor}|{entry.action}|"
                f"{entry.payload}|{prev}"
            )
            if hash_str(blob) != entry.entry_hash:
                return False, i
            prev = entry.entry_hash
        return True, None


@dataclass
class BREXState:
    mode: str = "cold_log"
    ingress: Dict[str, Any] = field(default_factory=lambda: dict(INGRESS))
    halted: bool = False
    flagged: bool = False
    bundle_manifest: Dict[str, str] = field(default_factory=dict)  # filename -> sha256
    log: ImmutableLog = field(default_factory=ImmutableLog)


STATE = BREXState()

# -------------------------
# Permission + consensus
# -------------------------
def has_perm(actor: str, perm: str) -> bool:
    return perm in AI_ROLES.get(actor, {}).get("permission", set())


def require_perm(actor: str, perm: str) -> None:
    if not has_perm(actor, perm):
        raise PermissionError(f"{actor} lacks permission: {perm}")


# Simple 2-of-3 consensus gate for ADMIN elevation operations
CONSENSUS_POOL = {"REX", "POTTS", "FAZZ"}  # voters


def require_consensus(votes: Set[str], needed: int = 2) -> None:
    valid = votes.intersection(CONSENSUS_POOL)
    if len(valid) < needed:
        raise PermissionError(
            "Consensus required: "
            f"{needed}-of-{len(CONSENSUS_POOL)} (got {len(valid)} valid votes)."
        )


# -------------------------
# Mode guards
# -------------------------
def mode_allows(action: str) -> bool:
    if STATE.mode == "cold_log":
        return action in {"echo_state", "append_log", "verify_log", "list_bundle_contents"}
    return True


# -------------------------
# Public API (suggested tip + essentials)
# -------------------------
def echo_state() -> Dict[str, Any]:
    STATE.log.append(
        "REX",
        "echo_state",
        {"mode": STATE.mode, "halted": STATE.halted, "flagged": STATE.flagged},
    )
    return {
        "mode": STATE.mode,
        "ingress": STATE.ingress,
        "halted": STATE.halted,
        "flagged": STATE.flagged,
        "bundle_items": len(STATE.bundle_manifest),
        "log_len": len(STATE.log.chain),
    }


def set_mode(actor: str, mode: str) -> None:
    if actor == "ADMIN":
        require_perm(actor, "bundle_control")
    else:
        require_perm(actor, "trigger")
    if mode not in MODES:
        raise ValueError(f"Invalid mode: {mode}")
    STATE.mode = mode
    STATE.log.append(actor, "set_mode", {"mode": mode})


def fazz_flag(actor: str, reason: str) -> None:
    require_perm(actor, "drift_detect")
    STATE.flagged = True
    STATE.log.append(actor, "fazz_flag", {"reason": reason})


def fazz_halt(actor: str, reason: str) -> None:
    require_perm(actor, "halt")
    STATE.halted = True
    STATE.log.append(actor, "fazz_halt", {"reason": reason})


def admin_release_scope(actor: str, votes: Set[str], scope: str) -> None:
    require_perm(actor, "release_scope")
    require_consensus(votes, needed=2)
    # Release scope is a governance decision; does not imply mutation allowed.
    STATE.log.append(actor, "admin_release_scope", {"votes": sorted(votes), "scope": scope})


def admin_override_mutation(actor: str, votes: Set[str], allow: bool) -> None:
    require_perm(actor, "manual_overrides")
    require_consensus(votes, needed=2)
    STATE.ingress["mutation"] = "allowed" if allow else "forbidden"
    STATE.log.append(
        actor,
        "admin_override_mutation",
        {"votes": sorted(votes), "mutation": STATE.ingress["mutation"]},
    )


def ingest_bundle_hashes(actor: str, manifest: Dict[str, str]) -> None:
    # manifest: {filename: sha256}
    require_perm(actor, "cache")
    if STATE.ingress.get("verify_hashes") is True:
        # Accept as declared manifest; actual file hashing happens outside this scaffold.
        STATE.bundle_manifest.update(manifest)
        STATE.log.append(actor, "ingest_bundle_hashes", {"count": len(manifest)})
    else:
        STATE.log.append(
            actor,
            "ingest_bundle_hashes_skipped",
            {"reason": "verify_hashes=false"},
        )


def list_bundle_contents() -> Dict[str, str]:
    # Read-only safe for cold_log
    STATE.log.append("POTTS", "list_bundle_contents", {"count": len(STATE.bundle_manifest)})
    return dict(STATE.bundle_manifest)


def verify_log_chain() -> Dict[str, Any]:
    ok, idx = STATE.log.verify_chain()
    STATE.log.append("POTTS", "verify_log_chain", {"ok": ok, "bad_index": idx})
    return {"ok": ok, "bad_index": idx}


# -------------------------
# Activation Banner
# -------------------------
def print_activation_banner() -> None:
    print("🧠 BREX Terminal Activated")
    print("🔒 Immutable Memory Channels Engaged")
    print("🐶 REX | 🤖 ADMIN | 👨‍⚖️ POTTS | 🔐 FAZZ Ready")
    print("💡 Tip: use `echo_state()` to preview current synced state.")


if __name__ == "__main__":
    print_activation_banner()
