#!/usr/bin/env python3
"""Activate and verify the REXFORT BLACK preservation profile.

REXFORT BLACK is a local evidence-preservation policy, not an encryption or
authentication mechanism.  Activation seals a policy packet around a
court-safe source record without recording challenge answers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROFILE = "REXFORT_BLACK"
SCHEMA_VERSION = "1.1.0"
FORBIDDEN_KEYS = {
    "answer",
    "answers",
    "secret_answer",
    "secret_answers",
    "question_answers",
    "recovery_answers",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_forbidden_keys(value: Any, prefix: str = "$") -> list[str]:
    """Return locations of fields that could contain challenge answers."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            location = f"{prefix}.{key}"
            if str(key).lower() in FORBIDDEN_KEYS:
                found.append(location)
            found.extend(find_forbidden_keys(child, location))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(find_forbidden_keys(child, f"{prefix}[{index}]"))
    return found


def validate_source(source: dict[str, Any]) -> None:
    if source.get("do_not_record_secret_answers") is not True:
        raise ValueError("source must set do_not_record_secret_answers to true")
    if source.get("key_reference_marker") != "three_and_six":
        raise ValueError("source must preserve the marker as three_and_six")
    forbidden = find_forbidden_keys(source)
    if forbidden:
        raise ValueError(
            "source contains forbidden challenge-answer fields: " + ", ".join(forbidden)
        )
    classification = source.get("evidence_classification")
    if not isinstance(classification, dict):
        raise ValueError("source must contain evidence_classification")
    for field in ("fact", "user_reported", "needs_corroboration"):
        if not isinstance(classification.get(field), list):
            raise ValueError(f"evidence_classification.{field} must be a list")
    if not source.get("court_safe_summary"):
        raise ValueError("source must contain court_safe_summary")


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, indent=2, ensure_ascii=False)
            file_obj.write("\n")
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def portable_source_path(source_path: Path, output_path: Path) -> str:
    """Represent the source relative to the packet so the pair can be moved."""
    return os.path.relpath(source_path.resolve(), output_path.parent.resolve())


def build_packet(
    source_path: Path, output_path: Path, source: dict[str, Any]
) -> dict[str, Any]:
    source_hash = sha256_file(source_path)
    protected_claim = {
        "reported_function": source.get("reported_function"),
        "reported_access_condition": source.get("reported_access_condition"),
        "reported_participants": source.get("reported_participants", []),
        "key_reference_marker": source["key_reference_marker"],
        "court_safe_summary": source["court_safe_summary"],
    }
    packet: dict[str, Any] = {
        "profile": PROFILE,
        "schema_version": SCHEMA_VERSION,
        "activated_at_utc": utc_now(),
        "status": "ACTIVE_LOCAL_POLICY",
        "scope": "repository_activation_packet_only",
        "source_record": {
            "path": portable_source_path(source_path, output_path),
            "path_basis": "activation_packet_directory",
            "sha256": source_hash,
        },
        "integrity_assurance": {
            "mechanism": "sha256_digest",
            "authenticates_author": False,
            "note": "A digest detects changes against this packet; it is not a digital signature.",
        },
        "protected_claim": protected_claim,
        "evidence_classification": source["evidence_classification"],
        "controls": {
            "deny_secret_answer_recording": True,
            "preserve_marker_only": True,
            "originals_read_only_by_policy": True,
            "no_automatic_deletion": True,
            "no_automatic_unlock": True,
            "human_approval_required_for_export": True,
            "automations_default_to_quarantine": True,
            "corroboration_required_before_fact_elevation": True,
        },
        "limitations": [
            "Activation does not prove the underlying user-reported claims.",
            "Activation does not encrypt, lock, or unlock an external vault.",
            "Operating-system and cloud permissions require separate enforcement.",
        ],
    }
    packet["packet_sha256"] = sha256_bytes(canonical_bytes(packet))
    return packet


def activate(source_path: Path, output_path: Path) -> dict[str, Any]:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    if not isinstance(source, dict):
        raise ValueError("source record must be a JSON object")
    validate_source(source)
    packet = build_packet(source_path, output_path, source)
    atomic_write_json(output_path, packet)
    return packet


def resolve_source_path(packet_path: Path, recorded_path: str) -> Path:
    source_path = Path(recorded_path)
    if source_path.is_absolute():
        return source_path
    return packet_path.resolve().parent / source_path


def verify(
    packet_path: Path, source_override: Path | None = None
) -> tuple[bool, list[str]]:
    try:
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return False, [f"activation packet unreadable: {error}"]
    if not isinstance(packet, dict):
        return False, ["activation packet must be a JSON object"]
    errors: list[str] = []
    if packet.get("profile") != PROFILE:
        errors.append("profile mismatch")
    if packet.get("status") != "ACTIVE_LOCAL_POLICY":
        errors.append("profile is not active")
    expected = packet.get("packet_sha256")
    unsigned = dict(packet)
    unsigned.pop("packet_sha256", None)
    actual = sha256_bytes(canonical_bytes(unsigned))
    if expected != actual:
        errors.append("packet SHA-256 mismatch")
    forbidden = find_forbidden_keys(packet)
    if forbidden:
        errors.append("forbidden challenge-answer fields present")
    source_info = packet.get("source_record", {})
    if not isinstance(source_info, dict):
        return False, errors + ["source_record must be an object"]
    recorded_path = source_info.get("path")
    if not isinstance(recorded_path, str) or not recorded_path:
        return False, errors + ["source record path is missing"]
    source_path = source_override or resolve_source_path(packet_path, recorded_path)
    if not source_path.is_file():
        errors.append("source record is unavailable")
    elif sha256_file(source_path) != source_info.get("sha256"):
        errors.append("source record SHA-256 mismatch")
    return not errors, errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Activate or verify REXFORT BLACK.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    activate_parser = subparsers.add_parser("activate")
    activate_parser.add_argument("--source", required=True, type=Path)
    activate_parser.add_argument("--output", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("packet", type=Path)
    verify_parser.add_argument(
        "--source",
        type=Path,
        help="Optional source-record location when it has moved separately from the packet.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "activate":
        packet = activate(args.source, args.output)
        print(f"REXFORT BLACK: {packet['status']}")
        print(f"Packet: {args.output}")
        print(f"SHA-256: {packet['packet_sha256']}")
        print("Secret answers recorded: 0")
        return 0
    valid, errors = verify(args.packet, args.source)
    if valid:
        print("REXFORT BLACK verification: PASS")
        return 0
    print("REXFORT BLACK verification: FAIL")
    for error in errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
