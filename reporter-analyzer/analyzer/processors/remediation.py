"""Build package and remediation highlights for the initial report."""

from collections import defaultdict
from typing import Any

from analyzer.normalizers.severity import highest_severity, severity_rank


def _package_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    package = finding.get("package") or {}
    return (
        package.get("name") or "",
        package.get("version") or "",
        package.get("type") or "unknown",
    )


def top_affected_packages(findings: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Group findings by affected package and return the most important ones."""
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}

    for finding in findings:
        key = _package_key(finding)
        if key not in grouped:
            grouped[key] = {
                "package_name": key[0],
                "package_version": key[1],
                "package_type": key[2],
                "finding_count": 0,
                "fixable_count": 0,
                "_severities": [],
            }
        grouped[key]["finding_count"] += 1
        grouped[key]["fixable_count"] += 1 if finding.get("fix", {}).get("fix_available") else 0
        grouped[key]["_severities"].append(finding.get("severity", "unknown"))

    records = []
    for item in grouped.values():
        highest = highest_severity(item.pop("_severities"))
        item["highest_severity"] = highest
        records.append(item)

    return sorted(
        records,
        key=lambda record: (
            severity_rank(record["highest_severity"]),
            -record["finding_count"],
            record["package_name"],
        ),
    )[:limit]


def remediation_highlights(findings: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Group fixable findings into concise remediation actions."""
    grouped: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = defaultdict(
        lambda: {
            "package_name": "",
            "package_version": "",
            "fixed_versions": [],
            "finding_count": 0,
            "_severities": [],
        }
    )

    for finding in findings:
        fix = finding.get("fix") or {}
        fixed_versions = tuple(fix.get("fixed_versions") or [])
        if not fixed_versions:
            continue

        package = finding.get("package") or {}
        key = (package.get("name") or "", package.get("version") or "", fixed_versions)
        item = grouped[key]
        item["package_name"] = key[0]
        item["package_version"] = key[1]
        item["fixed_versions"] = list(fixed_versions)
        item["finding_count"] += 1
        item["_severities"].append(finding.get("severity", "unknown"))

    records = []
    for item in grouped.values():
        highest = highest_severity(item.pop("_severities"))
        item["highest_severity"] = highest
        records.append(item)

    return sorted(
        records,
        key=lambda record: (
            severity_rank(record["highest_severity"]),
            -record["finding_count"],
            record["package_name"],
        ),
    )[:limit]
