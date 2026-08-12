"""REXCS OpenAI gateway.

Security posture:
- reads OPENAI_API_KEY from the process environment only;
- never logs or returns the API key;
- blocks sensitive/personal evidence from remote model calls by default;
- returns source/audit metadata separately from model output;
- does not mutate source evidence.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from openai import OpenAI


EvidenceClass = Literal["synthetic", "public", "internal", "sensitive"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RexOpenAIConfig:
    model: str = os.getenv("REX_OPENAI_MODEL", "gpt-5")
    allow_remote_evidence: bool = os.getenv("REX_ALLOW_REMOTE_EVIDENCE", "0") == "1"


class RexOpenAIGateway:
    """Thin, auditable wrapper around the OpenAI Responses API."""

    def __init__(self, config: Optional[RexOpenAIConfig] = None) -> None:
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not configured in the backend environment")
        self.config = config or RexOpenAIConfig()
        self.client = OpenAI()

    def _check_remote_scope(self, evidence_class: EvidenceClass) -> None:
        if evidence_class == "sensitive" and not self.config.allow_remote_evidence:
            raise PermissionError(
                "Sensitive evidence transmission is disabled. "
                "Set REX_ALLOW_REMOTE_EVIDENCE=1 only after explicit human approval."
            )

    def run(
        self,
        *,
        task: str,
        payload: Dict[str, Any],
        evidence_class: EvidenceClass = "internal",
        source_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run one evidence-first model task and return output plus safe audit metadata."""
        self._check_remote_scope(evidence_class)

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
            "evidence_class": evidence_class,
            "source_reference": source_reference,
            "payload": payload,
        }

        response = self.client.responses.create(
            model=self.config.model,
            instructions=instructions,
            input=json.dumps(request_input, ensure_ascii=False, default=str),
        )

        return {
            "output_text": response.output_text,
            "audit": {
                "provider": "openai",
                "response_id": getattr(response, "id", None),
                "model_requested": self.config.model,
                "evidence_class": evidence_class,
                "source_reference": source_reference,
                "requested_at_utc": utc_now_iso(),
                "source_mutated": False,
            },
        }


def main() -> None:
    """Safe smoke entry point using synthetic data only."""
    gateway = RexOpenAIGateway()
    result = gateway.run(
        task="Classify this synthetic record using the REXCS evidence-status rules.",
        evidence_class="synthetic",
        source_reference="synthetic-smoke-test",
        payload={"record": "A test document states that an event occurred."},
    )
    print(result["output_text"])


if __name__ == "__main__":
    main()
