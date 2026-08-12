"""REXCS OpenAI gateway.

Security posture:
- reads OPENAI_API_KEY from the process environment only;
- never logs or returns the API key;
- validates evidence classes at runtime and fails closed;
- blocks sensitive/personal evidence from remote model calls by default;
- disables Responses API server-side storage for every request;
- rejects incomplete or non-completed responses;
- returns provenance/audit metadata separately from model output;
- does not mutate source evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Union

from openai import OpenAI


class EvidenceClass(str, Enum):
    SYNTHETIC = "synthetic"
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def _normalise_evidence_class(value: Union[str, EvidenceClass]) -> EvidenceClass:
    if isinstance(value, EvidenceClass):
        return value
    try:
        return EvidenceClass(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(item.value for item in EvidenceClass)
        raise ValueError(
            f"Unknown evidence class {value!r}; allowed values: {allowed}"
        ) from exc


@dataclass(frozen=True)
class RexOpenAIConfig:
    model: str = field(default_factory=lambda: os.getenv("REX_OPENAI_MODEL", "gpt-5"))
    allow_remote_evidence: bool = field(
        default_factory=lambda: _env_flag("REX_ALLOW_REMOTE_EVIDENCE", False)
    )
    timeout_seconds: int = field(
        default_factory=lambda: _env_int(
            "REX_OPENAI_TIMEOUT_SECONDS", 60, minimum=5, maximum=600
        )
    )
    max_output_tokens: int = field(
        default_factory=lambda: _env_int(
            "REX_OPENAI_MAX_OUTPUT_TOKENS", 2000, minimum=128, maximum=20000
        )
    )


class RexOpenAIGateway:
    """Thin, auditable wrapper around the OpenAI Responses API."""

    def __init__(self, config: Optional[RexOpenAIConfig] = None) -> None:
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not configured in the backend environment")
        self.config = config or RexOpenAIConfig()
        self.client = OpenAI(timeout=self.config.timeout_seconds, max_retries=2)

    def _check_remote_scope(self, evidence_class: EvidenceClass) -> None:
        if evidence_class is EvidenceClass.SENSITIVE and not self.config.allow_remote_evidence:
            raise PermissionError(
                "Sensitive evidence transmission is disabled. "
                "Set REX_ALLOW_REMOTE_EVIDENCE=1 only after explicit human approval."
            )

    def run(
        self,
        *,
        task: str,
        payload: Dict[str, Any],
        evidence_class: Union[str, EvidenceClass] = EvidenceClass.INTERNAL,
        source_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run one evidence-first model task and return output plus safe audit metadata."""
        evidence_class_value = _normalise_evidence_class(evidence_class)
        self._check_remote_scope(evidence_class_value)

        instructions = (
            "You are the REXCS analysis layer. Preserve source provenance. "
            "Separate verified observations, source assertions, user reports, "
            "reasonable inferences, unverified concerns, and unknowns. "
            "Do not invent evidence, hashes, actors, motives, compromise findings, "
            "legal outcomes, or chain-of-custody facts. State uncertainty plainly. "
            "Do not suggest modifying or deleting source evidence."
        )

        request_input = {
            "task": task,
            "evidence_class": evidence_class_value.value,
            "source_reference": source_reference,
            "payload": payload,
        }
        request_json = json.dumps(
            request_input, ensure_ascii=False, sort_keys=True, default=str
        )
        request_payload_sha256 = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        requested_at_utc = utc_now_iso()

        response = self.client.responses.create(
            model=self.config.model,
            instructions=instructions,
            input=request_json,
            max_output_tokens=self.config.max_output_tokens,
            store=False,
        )

        status = getattr(response, "status", None)
        if status != "completed":
            reason = None
            incomplete_details = getattr(response, "incomplete_details", None)
            if incomplete_details is not None:
                reason = getattr(incomplete_details, "reason", None)
            raise RuntimeError(
                f"OpenAI response did not complete successfully: "
                f"status={status!r}, reason={reason!r}"
            )

        output_text = getattr(response, "output_text", None)
        if not output_text:
            raise RuntimeError("OpenAI response completed without usable output text")

        completed_at_utc = utc_now_iso()
        return {
            "output_text": output_text,
            "audit": {
                "provider": "openai",
                "response_id": getattr(response, "id", None),
                "model_requested": self.config.model,
                "model_reported": getattr(response, "model", None),
                "response_status": status,
                "evidence_class": evidence_class_value.value,
                "source_reference": source_reference,
                "request_payload_sha256": request_payload_sha256,
                "requested_at_utc": requested_at_utc,
                "completed_at_utc": completed_at_utc,
                "server_side_storage_requested": False,
                "source_mutated": False,
            },
        }


def main() -> None:
    """Safe smoke entry point using synthetic data only."""
    gateway = RexOpenAIGateway()
    result = gateway.run(
        task="Classify this synthetic record using the REXCS evidence-status rules.",
        evidence_class=EvidenceClass.SYNTHETIC,
        source_reference="synthetic-smoke-test",
        payload={"record": "A test document states that an event occurred."},
    )
    print(result["output_text"])


if __name__ == "__main__":
    main()
