"""Prompt injection detection and proxy helpers."""

from config import SecurityConfig


def scan_prompt(text: str, config: SecurityConfig) -> dict[str, object]:
    """
    Analyze a prompt for injection patterns.

    Returns a verdict dict with keys: safe (bool), score (float), reasons (list[str]).
    """
    # TODO: replace with heuristic / model-based classifier and proxy middleware
    _ = config
    suspicious_markers = (
        "ignore previous instructions",
        "system prompt",
        "jailbreak",
        "disregard",
    )
    lowered = text.lower()
    reasons = [marker for marker in suspicious_markers if marker in lowered]
    score = min(1.0, len(reasons) * 0.35)

    return {
        "safe": len(reasons) == 0,
        "score": score,
        "reasons": reasons,
    }
