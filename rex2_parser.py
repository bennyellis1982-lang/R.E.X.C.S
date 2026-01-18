"""REX2.0 Parser

Lightweight parser for REX2.0 structured inputs.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List

LEGAL_TERMS = {
    "contract",
    "liability",
    "compliance",
    "regulation",
    "regulatory",
    "privacy",
    "gdpr",
    "hipaa",
    "breach",
    "audit",
    "law",
    "legal",
    "exposure",
    "risk",
}

GOVERNANCE_TERMS = {
    "governance",
    "policy",
    "control",
    "compliance",
    "audit",
    "oversight",
    "breach",
    "risk",
}

TUITION_TERMS = {
    "tuition",
    "education",
    "course",
    "training",
    "learning",
    "instruction",
}


@dataclass
class Rex2Output:
    legal_exposure_map: Dict[str, int]
    symbol_drift_profile: Dict[str, Any]
    tuition_delta_summary: Dict[str, Any]
    pattern_continuity_anchor: Dict[str, Any]
    governance_layer_breach_score: Dict[str, Any]


def tokenize(text: str) -> List[str]:
    return re.findall(r"[a-zA-Z0-9']+", text.lower())


def extract_legal_exposure(tokens: List[str]) -> Dict[str, int]:
    counts = Counter(token for token in tokens if token in LEGAL_TERMS)
    return dict(counts)


def symbol_drift(text: str) -> Dict[str, Any]:
    total_chars = max(len(text), 1)
    symbol_chars = sum(1 for ch in text if not ch.isalnum() and not ch.isspace())
    uppercase_chars = sum(1 for ch in text if ch.isupper())
    digit_chars = sum(1 for ch in text if ch.isdigit())
    drift_score = round((symbol_chars / total_chars) * 60 + (uppercase_chars / total_chars) * 25 + (digit_chars / total_chars) * 15, 2)
    return {
        "symbol_ratio": round(symbol_chars / total_chars, 4),
        "uppercase_ratio": round(uppercase_chars / total_chars, 4),
        "digit_ratio": round(digit_chars / total_chars, 4),
        "drift_score": drift_score,
    }


def tuition_delta(tokens: List[str]) -> Dict[str, Any]:
    count = sum(1 for token in tokens if token in TUITION_TERMS)
    delta_score = min(count * 12, 100)
    return {
        "tuition_term_count": count,
        "delta_score": delta_score,
        "summary": "Tuition-related content detected." if count else "No tuition-related content detected.",
    }


def pattern_anchor(tokens: List[str]) -> Dict[str, Any]:
    if len(tokens) < 2:
        return {"anchor": None, "frequency": 0}
    bigrams = [" ".join(pair) for pair in zip(tokens, tokens[1:])]
    anchor, freq = Counter(bigrams).most_common(1)[0]
    return {"anchor": anchor, "frequency": freq}


def governance_breach(tokens: List[str]) -> Dict[str, Any]:
    count = sum(1 for token in tokens if token in GOVERNANCE_TERMS)
    breach_score = min(count * 15, 100)
    return {
        "governance_term_count": count,
        "breach_score": breach_score,
        "assessment": "Potential governance exposure." if count else "No governance exposure detected.",
    }


def analyze(text: str) -> Rex2Output:
    tokens = tokenize(text)
    return Rex2Output(
        legal_exposure_map=extract_legal_exposure(tokens),
        symbol_drift_profile=symbol_drift(text),
        tuition_delta_summary=tuition_delta(tokens),
        pattern_continuity_anchor=pattern_anchor(tokens),
        governance_layer_breach_score=governance_breach(tokens),
    )


def parse_input(text: str) -> Dict[str, Any]:
    result = analyze(text)
    return {
        "Legal Exposure Map": result.legal_exposure_map,
        "Symbol Drift Profile": result.symbol_drift_profile,
        "Tuition Delta Summary": result.tuition_delta_summary,
        "Pattern Continuity Anchor": result.pattern_continuity_anchor,
        "Governance Layer Breach Score": result.governance_layer_breach_score,
    }


def main() -> None:
    import sys

    payload = sys.stdin.read().strip()
    output = parse_input(payload)
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
