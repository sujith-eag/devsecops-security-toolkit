"""HTML renderer for initial scan reports."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from analyzer.normalizers.severity import severity_rank

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
DEFAULT_TEMPLATE = "initial_report.html"
DEFAULT_LOGO = TEMPLATE_DIR / "logo.jpg"


def _safe_text(value: object, fallback: str = "") -> str:
    text = str(value or "").strip()
    return text or fallback


def _score(value: object) -> str:
    if isinstance(value, (int, float)):
        return f"{value:.3f}" if 0 < value < 1 else f"{value:.1f}"
    return "-"


def _format_datetime_minute(value: object) -> str:
    """Format ISO-like timestamps to a readable UTC value up to minutes."""
    raw = str(value or "").strip()
    if not raw:
        return "-"

    candidates = [raw]
    if raw.endswith("Z"):
        candidates.append(raw[:-1] + "+00:00")

    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
            return parsed.strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            continue

    return raw[:16] if len(raw) >= 16 else raw


def _short_description(value: object, limit: int = 360) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _fixed_versions(finding: dict[str, Any]) -> str:
    versions = (finding.get("fix") or {}).get("fixed_versions") or []
    return ", ".join(versions) if versions else "Not available"


def _unique_sorted(values: list[object]) -> list[str]:
    return sorted({str(value) for value in values if value not in (None, "")})


def _group_findings_by_package(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}

    for finding in findings:
        package = finding.get("package") or {}
        key = (
            package.get("name") or "Unknown package",
            package.get("version") or "Unknown version",
            package.get("type") or "unknown",
        )
        if key not in grouped:
            grouped[key] = {
                "package_name": key[0],
                "package_version": key[1],
                "package_type": key[2],
                "highest_severity": finding.get("severity", "unknown"),
                "finding_count": 0,
                "fixable_count": 0,
                "findings": [],
            }

        item = grouped[key]
        item["finding_count"] += 1
        item["fixable_count"] += 1 if (finding.get("fix") or {}).get("fix_available") else 0
        item["findings"].append(finding)
        if severity_rank(finding.get("severity")) < severity_rank(item["highest_severity"]):
            item["highest_severity"] = finding.get("severity", "unknown")

    return sorted(
        grouped.values(),
        key=lambda item: (
            severity_rank(item["highest_severity"]),
            -item["finding_count"],
            item["package_name"],
        ),
    )


def _build_package_overview(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a package-first overview table without repeating every CVE."""
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}

    for finding in findings:
        package = finding.get("package") or {}
        risk = finding.get("risk") or {}
        fix = finding.get("fix") or {}
        key = (
            package.get("name") or "Unknown package",
            package.get("version") or "Unknown version",
            package.get("type") or "unknown",
        )
        if key not in grouped:
            grouped[key] = {
                "package_name": key[0],
                "package_version": key[1],
                "package_type": key[2],
                "highest_severity": finding.get("severity", "unknown"),
                "fixed_versions": [],
                "max_cvss": None,
                "max_epss": None,
                "cves": [],
                "finding_count": 0,
            }

        item = grouped[key]
        item["finding_count"] += 1
        item["fixed_versions"].extend(fix.get("fixed_versions") or [])
        if finding.get("vulnerability_id"):
            item["cves"].append(finding["vulnerability_id"])
        if severity_rank(finding.get("severity")) < severity_rank(item["highest_severity"]):
            item["highest_severity"] = finding.get("severity", "unknown")
        if isinstance(risk.get("cvss_score"), (int, float)):
            item["max_cvss"] = max(item["max_cvss"] or 0, float(risk["cvss_score"]))
        if isinstance(risk.get("epss_score"), (int, float)):
            item["max_epss"] = max(item["max_epss"] or 0, float(risk["epss_score"]))

    overview = []
    for item in grouped.values():
        cves = _unique_sorted(item["cves"])
        fixed_versions = _unique_sorted(item["fixed_versions"])
        overview.append(
            {
                "package_name": item["package_name"],
                "package_type": item["package_type"],
                "highest_severity": item["highest_severity"],
                "current_version": item["package_version"],
                "fixed_version": ", ".join(fixed_versions) if fixed_versions else "Not available",
                "cvss": item["max_cvss"],
                "epss": item["max_epss"],
                "cve_summary": cves[0] if len(cves) == 1 else f"{len(cves)} CVEs",
                "finding_count": item["finding_count"],
            }
        )

    return sorted(
        overview,
        key=lambda item: (
            severity_rank(item["highest_severity"]),
            -(item["cvss"] or 0),
            -item["finding_count"],
            item["package_name"],
        ),
    )


def _logo_uri(logo_path: str = "") -> str:
    candidate = Path(logo_path) if logo_path else DEFAULT_LOGO
    if candidate.is_file():
        return candidate.resolve().as_uri()
    return ""


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["score"] = _score
    env.filters["short_description"] = _short_description
    env.filters["fixed_versions"] = _fixed_versions
    env.filters["safe_text"] = _safe_text
    env.filters["datetime_minute"] = _format_datetime_minute
    return env


def build_template_context(report_data: dict[str, Any], logo_path: str = "") -> dict[str, Any]:
    """Create presentation-specific context without changing report data JSON."""
    findings = report_data.get("findings") or []
    artifact = report_data.get("artifact") or {}
    return {
        "report": report_data,
        "artifact": artifact,
        "summary": report_data.get("vulnerability_summary") or {},
        "inventory": report_data.get("inventory_summary") or {},
        "sources": report_data.get("input_sources") or {},
        "highlights": report_data.get("top_highlights") or {},
        "severity_order": ["critical", "high", "medium", "low", "negligible", "unknown"],
        "package_overview": _build_package_overview(findings),
        "package_groups": _group_findings_by_package(findings),
        "logo_uri": _logo_uri(logo_path),
        "scan_time_display": _format_datetime_minute(artifact.get("scan_timestamp_utc")),
        "generated_time_display": _format_datetime_minute((report_data.get("report_context") or {}).get("generated_at")),
    }


def render_initial_html(report_data: dict[str, Any], output_path: str | Path, logo_path: str = "") -> str:
    """Render initial report HTML and write it to disk."""
    html = _environment().get_template(DEFAULT_TEMPLATE).render(build_template_context(report_data, logo_path))
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return html