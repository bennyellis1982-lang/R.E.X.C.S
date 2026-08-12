"""REXCS integration/source registry.

This module records what each external system is allowed to represent inside REXCS.
A registry entry is not proof that a service is currently connected or synchronised.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Tuple


class ConnectionState(str, Enum):
    CONNECTED = "connected"
    CONNECTOR_CAPABLE = "connector_capable"
    IMPORT_ONLY = "import_only"
    PLANNED = "planned"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Integration:
    key: str
    display_name: str
    role: str
    state: ConnectionState
    provenance_rule: str


INTEGRATIONS: Dict[str, Integration] = {
    "openai": Integration(
        key="openai",
        display_name="OpenAI / ChatGPT REX",
        role="AI analysis and structured workflow assistance",
        state=ConnectionState.CONNECTOR_CAPABLE,
        provenance_rule="Store model output as AI-generated analysis with provider and response metadata.",
    ),
    "gmail_rex": Integration(
        key="gmail_rex",
        display_name="Gmail Rex",
        role="Email evidence and operational communication intake",
        state=ConnectionState.CONNECTOR_CAPABLE,
        provenance_rule="Preserve Gmail message/thread IDs, sender, recipients, timestamps and attachments.",
    ),
    "github_rexcs": Integration(
        key="github_rexcs",
        display_name="GitHub R.E.X.C.S",
        role="Primary REXCS workflow/application repository",
        state=ConnectionState.CONNECTED,
        provenance_rule="Preserve repository, branch, commit SHA and file path for every code artifact.",
    ),
    "github_rexcore": Integration(
        key="github_rexcore",
        display_name="GitHub Rexcore",
        role="Core integrity and continuity repository",
        state=ConnectionState.CONNECTED,
        provenance_rule="Keep core-state artifacts separate from application-layer artifacts.",
    ),
    "github_rexarmery": Integration(
        key="github_rexarmery",
        display_name="GitHub REXARMERY",
        role="Private inventory and cyber-security build repository",
        state=ConnectionState.CONNECTED,
        provenance_rule="Preserve private-repository provenance and do not promote build notes into external-fact claims.",
    ),
    "grok": Integration(
        key="grok",
        display_name="Grok / xAI",
        role="External AI comparison and imported analysis",
        state=ConnectionState.IMPORT_ONLY,
        provenance_rule="Treat preserved Grok exports/emails/files as AI-generated records, not independent corroboration.",
    ),
    "claude": Integration(
        key="claude",
        display_name="Claude / Anthropic",
        role="External AI comparison and imported development material",
        state=ConnectionState.IMPORT_ONLY,
        provenance_rule="Treat preserved Claude exports/files as AI-generated records, not independent corroboration.",
    ),
    "slack": Integration(
        key="slack",
        display_name="Slack",
        role="Collaboration and operational records",
        state=ConnectionState.CONNECTOR_CAPABLE,
        provenance_rule="Preserve workspace, channel, thread, author and message timestamp.",
    ),
    "notion": Integration(
        key="notion",
        display_name="Notion",
        role="Project/case knowledge and documentation",
        state=ConnectionState.CONNECTOR_CAPABLE,
        provenance_rule="Historical summaries remain summaries until tied to primary evidence.",
    ),
    "google_drive": Integration(
        key="google_drive",
        display_name="Google Drive",
        role="Document and case-index source",
        state=ConnectionState.CONNECTOR_CAPABLE,
        provenance_rule="Preserve file ID, path/title, revision/source metadata and original bytes when acquired.",
    ),
    "dropbox": Integration(
        key="dropbox",
        display_name="Dropbox",
        role="Evidence mirror, media and manifest source",
        state=ConnectionState.CONNECTOR_CAPABLE,
        provenance_rule="Do not treat fuzzy search or Dropbox metadata alone as proof of source chronology or absence.",
    ),
    "outlook": Integration(
        key="outlook",
        display_name="Microsoft Outlook",
        role="Parallel email/account evidence source",
        state=ConnectionState.CONNECTOR_CAPABLE,
        provenance_rule="Preserve message IDs and account/source distinction from Gmail copies or forwards.",
    ),
}


def get_integration(key: str) -> Integration:
    return INTEGRATIONS[key]


def list_integrations() -> Tuple[Integration, ...]:
    return tuple(INTEGRATIONS.values())
