"""Severity normalization and sorting helpers."""

from analyzer.core.constants import SEVERITY_ORDER, SEVERITY_RANK

_SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "negligible": "negligible",
    "info": "negligible",
    "informational": "negligible",
    "unknown": "unknown",
    "": "unknown",
    None: "unknown",
}


def normalize_severity(value: object) -> str:
    """Normalize scanner severity into the report severity vocabulary."""
    if value is None:
        return "unknown"
    return _SEVERITY_ALIASES.get(str(value).strip().lower(), "unknown")


def severity_rank(severity: object) -> int:
    """Lower rank means higher severity."""
    return SEVERITY_RANK.get(normalize_severity(severity), SEVERITY_RANK["unknown"])


def empty_severity_counts() -> dict[str, int]:
    """Create a stable severity count object for reports."""
    return {severity: 0 for severity in SEVERITY_ORDER}


def highest_severity(values: list[str]) -> str:
    """Return the highest severity from a list."""
    if not values:
        return "unknown"
    return sorted((normalize_severity(value) for value in values), key=severity_rank)[0]
