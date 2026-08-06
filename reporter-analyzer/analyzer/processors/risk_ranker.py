"""Finding ranking and top vulnerability selection."""

from typing import Any

from analyzer.normalizers.severity import severity_rank


def finding_sort_key(finding: dict[str, Any]) -> tuple[int, float, float, int, str]:
    """Sort by severity, CVSS, EPSS, fixability, and vulnerability ID."""
    risk = finding.get("risk") or {}
    fix = finding.get("fix") or {}
    return (
        severity_rank(finding.get("severity")),
        -(risk.get("cvss_score") or 0.0),
        -(risk.get("epss_score") or 0.0),
        0 if fix.get("fix_available") else 1,
        finding.get("vulnerability_id") or "",
    )


def rank_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return findings in report priority order."""
    return sorted(findings, key=finding_sort_key)


def top_vulnerabilities(findings: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    """Return compact top vulnerability records for report highlights."""
    compact = []
    for finding in rank_findings(findings)[:limit]:
        package = finding.get("package") or {}
        fix = finding.get("fix") or {}
        risk = finding.get("risk") or {}
        compact.append(
            {
                "vulnerability_id": finding.get("vulnerability_id", ""),
                "severity": finding.get("severity", "unknown"),
                "package_name": package.get("name", ""),
                "package_version": package.get("version", ""),
                "fixed_versions": fix.get("fixed_versions", []),
                "cvss_score": risk.get("cvss_score"),
                "epss_score": risk.get("epss_score"),
                "fix_available": bool(fix.get("fix_available")),
            }
        )
    return compact
