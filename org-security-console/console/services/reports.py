"""Markdown report generation service.

Reports use QueryService only, so report logic is independent from the org-data
file layout.
"""

from datetime import datetime, timezone
from pathlib import Path


def _line_items(items, formatter, limit=None):
    selected = items[:limit] if limit else items
    if not selected:
        return "_None_\n"
    return "\n".join(formatter(item) for item in selected) + "\n"


class ReportService:
    def __init__(self, queries, reports_dir: Path):
        self.queries = queries
        self.reports_dir = reports_dir

    def org_report(self):
        overview = self.queries.overview()
        remediation = self.queries.remediation_items()
        artifacts = self.queries.artifacts()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return f"""# Organization Security Overview

Generated at: {now}

## Summary

- Artifacts: {overview['artifact_count']}
- Packages: {overview['package_count']}
- Vulnerabilities: {overview['vulnerability_count']}
- Findings: {overview['finding_count']}
- Fixable findings: {overview['fixable_count']}
- Remediation items: {overview['remediation_count']}
- Errors: {overview['error_count']}
- Warnings: {overview['warning_count']}

## Severity Totals

{chr(10).join(f'- {sev}: {count}' for sev, count in overview['severity_totals'].items())}

## Top Remediation Items

{_line_items(remediation, lambda x: f"- {x.get('highest_severity')} {x.get('vulnerability_id')} / {x.get('package_id')} → {', '.join(x.get('fixed_versions', []))} ({x.get('affected_artifact_count')} artifacts)", limit=25)}

## Most Affected Artifacts

{_line_items(artifacts, lambda x: f"- {(x.get('artifact') or {}).get('artifact_id')}: {x.get('finding_count')} findings, {x.get('fixable_count')} fixable", limit=25)}
"""

    def remediation_report(self):
        remediation = self.queries.remediation_items()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return f"""# Remediation Report

Generated at: {now}

{_line_items(remediation, lambda x: f"- **{x.get('highest_severity')}** `{x.get('vulnerability_id')}` affects `{x.get('package_id')}`; fixed versions: `{', '.join(x.get('fixed_versions', []))}`; artifacts: {x.get('affected_artifact_count')}")}
"""

    def artifact_report(self, artifact_id):
        detail = self.queries.artifact_detail(artifact_id)
        summary = detail.get("summary", {})
        artifact = detail.get("artifact", {})
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return f"""# Artifact Report: {artifact_id}

Generated at: {now}

## Artifact

- Type: {artifact.get('artifact_type', '')}
- Role: {artifact.get('artifact_role', '')}
- Project IDs: {', '.join(summary.get('project_ids', []))}

## Counts

- Packages: {summary.get('package_count', 0)}
- Vulnerable packages: {summary.get('vulnerable_package_count', 0)}
- Vulnerabilities: {summary.get('vulnerability_count', 0)}
- Findings: {summary.get('finding_count', 0)}
- Fixable: {summary.get('fixable_count', 0)}

## Severity Counts

{chr(10).join(f'- {sev}: {count}' for sev, count in (summary.get('severity_counts') or {}).items())}
"""

    def generate(self, report_type, artifact_id=None):
        if report_type == "org":
            return "org-security-report.md", self.org_report()
        if report_type == "remediation":
            return "remediation-report.md", self.remediation_report()
        if report_type == "artifact" and artifact_id:
            safe = artifact_id.replace("/", "_").replace(":", "_")
            return f"artifact-{safe}-report.md", self.artifact_report(artifact_id)
        raise ValueError(f"Unsupported report type: {report_type}")

    def write_report(self, report_type, artifact_id=None):
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        filename, content = self.generate(report_type, artifact_id)
        path = self.reports_dir / filename
        path.write_text(content, encoding="utf-8")
        return path
