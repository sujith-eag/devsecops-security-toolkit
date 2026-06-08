"""HTML renderer for initial scan reports."""

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from analyzer.normalizers.severity import severity_rank

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
DEFAULT_TEMPLATE = "initial_report.html"
DEFAULT_LOGO = TEMPLATE_DIR / "org-logo.png"


def _safe_text(value: object, fallback: str = "") -> str:
    text = str(value or "").strip()
    return text or fallback


def _score(value: object) -> str:
    if isinstance(value, (int, float)):
        return f"{value:.3f}" if 0 < value < 1 else f"{value:.1f}"
    return "-"


def _short_description(value: object, limit: int = 360) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _fixed_versions(finding: dict[str, Any]) -> str:
    versions = (finding.get("fix") or {}).get("fixed_versions") or []
    return ", ".join(versions) if versions else "No fixed version reported"


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
    return env


def build_template_context(report_data: dict[str, Any], logo_path: str = "") -> dict[str, Any]:
    """Create presentation-specific context without changing report data JSON."""
    findings = report_data.get("findings") or []
    return {
        "report": report_data,
        "artifact": report_data.get("artifact") or {},
        "summary": report_data.get("vulnerability_summary") or {},
        "inventory": report_data.get("inventory_summary") or {},
        "sources": report_data.get("input_sources") or {},
        "highlights": report_data.get("top_highlights") or {},
        "severity_order": ["critical", "high", "medium", "low", "negligible", "unknown"],
        "package_groups": _group_findings_by_package(findings),
        "logo_uri": _logo_uri(logo_path),
    }


def render_initial_html(report_data: dict[str, Any], output_path: str | Path, logo_path: str = "") -> str:
    """Render initial report HTML and write it to disk."""
    html = _environment().get_template(DEFAULT_TEMPLATE).render(build_template_context(report_data, logo_path))
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return html
