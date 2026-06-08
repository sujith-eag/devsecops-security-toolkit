"""Deduplicate normalized findings."""

from typing import Any


def _dedupe_key(finding: dict[str, Any]) -> tuple[str, str, str, str, str]:
    package = finding.get("package") or {}
    details = finding.get("details") or {}
    return (
        finding.get("vulnerability_id") or "",
        package.get("name") or "",
        package.get("version") or "",
        package.get("type") or "",
        details.get("location") or "",
    )


def _merge_unique(existing: list[str], new_values: list[str]) -> list[str]:
    return sorted(set(existing or []).union(str(value) for value in (new_values or []) if value))


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate findings while preserving useful merged detail."""
    merged: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}

    for finding in findings:
        key = _dedupe_key(finding)
        if key not in merged:
            merged[key] = finding
            continue

        current = merged[key]
        current["fix"]["fixed_versions"] = _merge_unique(
            current.get("fix", {}).get("fixed_versions", []),
            finding.get("fix", {}).get("fixed_versions", []),
        )
        current["fix"]["fix_available"] = bool(current["fix"]["fixed_versions"])
        current["risk"]["cwes"] = _merge_unique(
            current.get("risk", {}).get("cwes", []),
            finding.get("risk", {}).get("cwes", []),
        )
        current["details"]["urls"] = _merge_unique(
            current.get("details", {}).get("urls", []),
            finding.get("details", {}).get("urls", []),
        )

    return list(merged.values())
