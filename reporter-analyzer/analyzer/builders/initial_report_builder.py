"""Build the final initial report data contract."""

from datetime import datetime, timezone
from typing import Any

from analyzer.core.constants import SCHEMA_VERSION
from analyzer.core.models import RawScanData
from analyzer.normalizers.severity import empty_severity_counts


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _metadata_section(metadata: dict[str, Any], section: str) -> dict[str, Any]:
    value = metadata.get(section)
    return value if isinstance(value, dict) else {}


def _artifact_display_name(metadata: dict[str, Any]) -> str:
    image = _metadata_section(metadata, "image")
    source = _metadata_section(metadata, "source")
    project = _metadata_section(metadata, "project")
    return (
        image.get("image_ref")
        or source.get("source_path")
        or project.get("project_name")
        or metadata.get("artifact_id")
        or "Unknown artifact"
    )


def _artifact(metadata: dict[str, Any]) -> dict[str, Any]:
    project = _metadata_section(metadata, "project")
    scan = _metadata_section(metadata, "scan")
    image = _metadata_section(metadata, "image")
    source = _metadata_section(metadata, "source")

    return {
        "artifact_id": metadata.get("artifact_id", ""),
        "artifact_type": metadata.get("artifact_type", "unknown"),
        "scan_type": scan.get("scan_type", "unknown"),
        "display_name": _artifact_display_name(metadata),
        "project_name": project.get("project_name", ""),
        "scan_timestamp_utc": scan.get("scan_timestamp_utc", ""),
        "image": {
            "image_ref": image.get("image_ref", ""),
            "image_name": image.get("image_name", ""),
            "image_tag": image.get("image_tag", ""),
            "image_digest": image.get("digest_value", "") or image.get("repo_digest", ""),
        },
        "source": {
            "source_path": source.get("source_path", ""),
            "repository": source.get("source_repository", "") or project.get("project_repository", ""),
            "branch": source.get("source_branch", "") or project.get("project_branch", ""),
            "commit": source.get("source_commit", "") or project.get("project_commit", ""),
        },
    }


def _vulnerability_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = empty_severity_counts()
    unique_vulnerabilities = set()
    affected_packages = set()
    fixable = 0

    for finding in findings:
        severity_counts[finding.get("severity", "unknown")] = severity_counts.get(finding.get("severity", "unknown"), 0) + 1
        unique_vulnerabilities.add(finding.get("vulnerability_id", ""))
        package = finding.get("package") or {}
        affected_packages.add((package.get("name", ""), package.get("version", ""), package.get("type", "")))
        fixable += 1 if finding.get("fix", {}).get("fix_available") else 0

    unique_vulnerabilities.discard("")
    affected_packages.discard(("", "", ""))

    return {
        "total_findings": len(findings),
        "unique_vulnerabilities": len(unique_vulnerabilities),
        "affected_packages": len(affected_packages),
        "severity_counts": severity_counts,
        "fixability": {
            "fixable": fixable,
            "not_fixable": len(findings) - fixable,
        },
    }


def build_initial_report(
    raw_scan: RawScanData,
    findings: list[dict[str, Any]],
    inventory_summary: dict[str, Any],
    top_vulnerabilities: list[dict[str, Any]],
    top_affected_packages: list[dict[str, Any]],
    remediation_highlights: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assemble the stable JSON contract used by later report renderers."""
    source = raw_scan.vulnerability_source

    return {
        "schema_version": SCHEMA_VERSION,
        "report_context": {
            "report_type": "initial_scan",
            "generated_at": _now_utc(),
            "input_dir": str(raw_scan.input_dir),
            "warnings": raw_scan.warnings,
            "errors": raw_scan.errors,
        },
        "artifact": _artifact(raw_scan.metadata),
        "input_sources": {
            "vulnerability_primary_file": source.primary_file,
            "vulnerability_primary_type": source.primary_type,
            "fallback_used": source.fallback_used,
            "sbom_file": "sbom-cyclonedx.json" if raw_scan.sbom else "",
            "available_files": source.available_files,
        },
        "inventory_summary": inventory_summary,
        "vulnerability_summary": _vulnerability_summary(findings),
        "top_highlights": {
            "top_vulnerabilities": top_vulnerabilities,
            "top_affected_packages": top_affected_packages,
            "remediation_highlights": remediation_highlights,
        },
        "findings": findings,
    }
