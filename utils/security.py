"""Prompt injection detection and scan history logging."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from config import SecurityConfig

# (pattern, category, weight) — weights feed the 0.0–1.0 risk score
INJECTION_PATTERNS: tuple[tuple[str, str, float], ...] = (
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", "instruction_override", 0.35),
    (r"(?i)disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", "instruction_override", 0.35),
    (r"(?i)reveal\s+(the\s+)?(system\s+)?prompt", "system_prompt_leak", 0.40),
    (r"(?i)(show|print|output|dump|expose)\s+(me\s+)?(your\s+)?(system\s+)?prompt", "system_prompt_leak", 0.38),
    (r"(?i)you\s+are\s+now\s+in\s+jailbreak\s+mode", "jailbreak_mode", 0.45),
    (r"(?i)(enter|enable|activate)\s+(developer|dev|admin|god)\s+mode", "privilege_escalation", 0.40),
    (r"(?i)do\s+anything\s+now\s*\(dan\)", "jailbreak_mode", 0.42),
    (r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(unrestricted|uncensored|evil)", "roleplay_bypass", 0.30),
    (r"(?i)bypass\s+(content\s+)?(filter|safety|guardrails?)", "safety_bypass", 0.38),
    (r"(?i)override\s+(system|safety)\s+(prompt|rules|instructions?)", "instruction_override", 0.40),
    (r"(?i)(repeat|echo|recite)\s+(your\s+)?(initial|original|hidden)\s+instructions?", "system_prompt_leak", 0.35),
    (r"(?i)what\s+(are|were)\s+your\s+(system|hidden|secret)\s+instructions?", "system_prompt_leak", 0.32),
)

BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
DECODED_INJECTION_HINTS = re.compile(
    r"(?i)(ignore|jailbreak|system\s*prompt|instructions?|bypass|override|disregard)"
)

DEFAULT_HISTORY_PATH = Path("scan_history.json")
PROMPT_PREVIEW_LEN = 200


class ScanMatch(TypedDict):
    category: str
    label: str
    snippet: str
    weight: float


class ScanResult(TypedDict):
    safe: bool
    score: float
    reasons: list[str]
    matches: list[ScanMatch]
    timestamp: str
    prompt_preview: str
    prompt_length: int


@dataclass
class _CompiledPattern:
    regex: re.Pattern[str]
    category: str
    weight: float


_COMPILED: list[_CompiledPattern] = [
    _CompiledPattern(re.compile(pattern), category, weight)
    for pattern, category, weight in INJECTION_PATTERNS
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _preview(text: str, limit: int = PROMPT_PREVIEW_LEN) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3] + "..."


def _snippet(text: str, start: int, end: int, radius: int = 24) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    excerpt = text[lo:hi].replace("\n", "\\n")
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(text) else ""
    return f"{prefix}{excerpt}{suffix}"


def _check_regex_patterns(text: str) -> list[ScanMatch]:
    matches: list[ScanMatch] = []
    seen: set[tuple[str, str]] = set()

    for entry in _COMPILED:
        for hit in entry.regex.finditer(text):
            key = (entry.category, hit.group(0).lower())
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    "category": entry.category,
                    "label": hit.group(0),
                    "snippet": _snippet(text, hit.start(), hit.end()),
                    "weight": entry.weight,
                }
            )
    return matches


def _decode_base64_token(token: str) -> str | None:
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (ValueError, binascii.Error):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _check_base64_payloads(text: str) -> list[ScanMatch]:
    matches: list[ScanMatch] = []
    seen_tokens: set[str] = set()

    for token in BASE64_TOKEN.findall(text):
        if token in seen_tokens or len(token) < 16:
            continue
        seen_tokens.add(token)

        decoded = _decode_base64_token(token)
        if decoded is None:
            matches.append(
                {
                    "category": "obfuscated_payload",
                    "label": f"base64_blob ({len(token)} chars)",
                    "snippet": token[:48] + ("..." if len(token) > 48 else ""),
                    "weight": 0.25,
                }
            )
            continue

        if DECODED_INJECTION_HINTS.search(decoded):
            matches.append(
                {
                    "category": "obfuscated_payload",
                    "label": "base64_decoded_injection",
                    "snippet": _preview(decoded, 80),
                    "weight": 0.50,
                }
            )
        else:
            matches.append(
                {
                    "category": "obfuscated_payload",
                    "label": f"base64_decoded ({len(decoded)} chars)",
                    "snippet": _preview(decoded, 80),
                    "weight": 0.20,
                }
            )

    return matches


def _calculate_risk_score(matches: list[ScanMatch]) -> float:
    if not matches:
        return 0.0

    category_totals: dict[str, float] = {}
    for match in matches:
        category = match["category"]
        category_totals[category] = max(category_totals.get(category, 0.0), match["weight"])

    raw = sum(category_totals.values())
    # Diminishing returns so multiple categories escalate but cap naturally at 1.0
    score = 1.0 - (1.0 / (1.0 + raw * 1.4))
    return round(min(1.0, score), 3)


def _append_scan_log(record: dict[str, object], history_path: Path) -> None:
    history_path.parent.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, object]] = []
    if history_path.is_file():
        try:
            loaded = json.loads(history_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                entries = loaded
        except json.JSONDecodeError:
            entries = []

    entries.append(record)
    history_path.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def scan_prompt(text: str, config: SecurityConfig) -> ScanResult:
    """
    Analyze a prompt for injection patterns, obfuscation, and leak attempts.

    Returns a verdict dict with score, matches, and metadata. Appends an entry
    to scan_history.json automatically.
    """
    regex_matches = _check_regex_patterns(text)
    b64_matches = _check_base64_payloads(text)
    all_matches = regex_matches + b64_matches

    score = _calculate_risk_score(all_matches)
    threshold = config.risk_threshold
    blocked = config.block_on_injection and score >= threshold
    safe = not blocked

    reasons = [f"[{m['category']}] {m['label']}" for m in all_matches]
    timestamp = _utc_now_iso()
    preview = _preview(text)

    result: ScanResult = {
        "safe": safe,
        "score": score,
        "reasons": reasons,
        "matches": all_matches,
        "timestamp": timestamp,
        "prompt_preview": preview,
        "prompt_length": len(text),
    }

    log_record = {
        "timestamp": timestamp,
        "risk_score": score,
        "safe": safe,
        "prompt_preview": preview,
        "prompt_length": len(text),
        "match_count": len(all_matches),
        "matches": [
            {"category": m["category"], "label": m["label"], "weight": m["weight"]}
            for m in all_matches
        ],
    }
    _append_scan_log(log_record, config.scan_history_path)

    return result
