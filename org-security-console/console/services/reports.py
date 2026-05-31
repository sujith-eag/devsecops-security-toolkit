"""Markdown report generation service.

Reports use QueryService only. They do not read org-data files directly, keeping
report generation aligned with the same production index abstraction used by the UI.
"""

from datetime import datetime, timezone
from pathlib import Path


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_filename(value):
    return "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in str(value or "unknown"))[:120]


def list_lines(items, formatter, empty="_None_", limit=None):
    selected = items[:limit] if limit else items
    if not selected:
        return f"{empty}\n"
    return "\n".join(formatter(item) for item in selected) + "\n"


def severity_summary(counts):
    if not counts:
        return "_No severity data_\n"
    return "\n".join(f"- {sev}: {count}" for sev, count in counts.items()) + "\n"


class ReportService:
    """Generates Markdown reports from query service data."""

    def __init__(self, queries, reports_dir: Path):
        self.queries = queries
        self.reports_dir = reports_dir

    def org_report(self):
        overview = self.queries.overview()
        remediation = self.queries.remediation_items()[:25]
        artifacts = self.queries.artifacts()[:25]
        health = self.queries.run_health()
        return f"""# Organization Security Report

Generated at: {now_utc()}
Last data update: {overview.get('last_updated')}

## Summary

- Artifacts: {overview.get('artifact_count')}
- Packages: {overview.get('package_count')}
- Vulnerabilities: {overview.get('vulnerability_count')}
- Findings: {overview.get('finding_count')}
- Fixable findings: {overview.get('fixable_count')}
- Non-fixable findings: {overview.get('not_fixable_count')}
- Remediation actions: {overview.get('remediation_action_count')}
- Data errors: {overview.get('error_count')}
- Data warnings: {overview.get('warning_count')}

## Severity Summary

{severity_summary(overview.get('severity_totals'))}

## Top Remediation Actions

{list_lines(remediation, lambda x: f"- **{x.get('highest_severity')}** {x.get('vulnerability_id')} affects `{x.get('package_id')}`; upgrade to: {', '.join(x.get('fixed_versions', []))}; artifacts: {x.get('affected_artifact_count')}")}

## Highest Risk Artifacts

{list_lines(artifacts, lambda x: f"- `{(x.get('artifact') or {}).get('artifact_id')}`: {x.get('finding_count')} findings, {x.get('fixable_count')} fixable, critical/high: {x.get('critical_high_count')}")}

## Data Health

- Run errors: {len(health.get('errors', []))}
- Reference warnings: {len(health.get('warnings', []))}
- Index warnings: {(health.get('index_validation') or {}).get('warning_count', 0)}
"""

    def remediation_report(self):
        remediation = self.queries.remediation_items()
        return f"""# Remediation Report

Generated at: {now_utc()}

This report lists fixable vulnerability findings grouped by vulnerability, package, and fixed version.

## Remediation Actions

{list_lines(remediation, lambda x: f"- **{x.get('highest_severity')}** `{x.get('vulnerability_id')}` → package `{x.get('package_id')}` → upgrade to `{', '.join(x.get('fixed_versions', []))}`; affected artifacts: {x.get('affected_artifact_count')}; affected projects: {x.get('affected_project_count')}")}
"""

    def artifact_report(self, target_id):
        detail = self.queries.artifact_detail(target_id)
        summary = detail.get("summary", {})
        artifact = detail.get("artifact", {})
        return f"""# Artifact Security Report

Generated at: {now_utc()}

## Artifact

- Artifact ID: `{artifact.get('artifact_id')}`
- Type: {artifact.get('artifact_type')}
- Role: {artifact.get('artifact_role')}
- Projects: {', '.join(detail.get('project_ids', [])) or 'No project metadata'}

## Security Summary

- Security status: {summary.get('security_status')}
- Packages: {summary.get('package_count')}
- Vulnerabilities: {len(summary.get('vulnerability_ids', []))}
- Findings: {summary.get('finding_count')}
- Fixable findings: {summary.get('fixable_count')}
- Critical/High findings: {summary.get('critical_high_count')}

## Severity Summary

{severity_summary(summary.get('severity_counts'))}

## Vulnerabilities

{list_lines(detail.get('vulnerabilities', []), lambda x: f"- **{x.get('highest_severity') or x.get('severity')}** `{x.get('vulnerability_id')}` ({x.get('security_status')}); fixed versions: {', '.join(x.get('fixed_versions', [])) or 'none known'}")}

## Vulnerable Packages

{list_lines(detail.get('packages', []), lambda x: f"- `{x.get('package_name')}` `{x.get('package_version')}` ({x.get('package_type')}) - {x.get('security_status')}; fixed versions: {', '.join(x.get('fixed_versions', [])) or 'none known'}")}
"""

    def vulnerability_report(self, target_id):
        detail = self.queries.vulnerability_detail(target_id)
        idx = detail.get("index", {})
        ent = detail.get("entity", {})
        return f"""# Vulnerability Impact Report

Generated at: {now_utc()}

## Vulnerability

- ID: `{idx.get('vulnerability_id') or ent.get('vulnerability_id')}`
- Severity: {idx.get('highest_severity') or idx.get('severity') or ent.get('severity')}
- Status: {idx.get('security_status')}
- Affected artifacts: {len(idx.get('artifact_ids', []))}
- Affected packages: {len(idx.get('package_ids', []))}
- Fixable findings: {idx.get('fixable_count')}
- CWEs: {', '.join(ent.get('cwes', []) or idx.get('cwes', []) or []) or 'not available'}

## Description

{ent.get('description') or 'No description available.'}

## Affected Packages

{list_lines(detail.get('packages', []), lambda x: f"- `{x.get('package_name')}` `{x.get('package_version')}` ({x.get('package_type')}) - {x.get('security_status')}; fixed versions: {', '.join(x.get('fixed_versions', [])) or 'none known'}")}

## Affected Artifacts

{list_lines(detail.get('artifacts', []), lambda x: f"- `{(x.get('artifact') or {}).get('artifact_id')}` - {x.get('security_status')}; findings: {x.get('finding_count')}; fixable: {x.get('fixable_count')}")}
"""

    def package_report(self, target_id):
        detail = self.queries.package_detail(target_id)
        idx = detail.get("index", {})
        return f"""# Package Security Report

Generated at: {now_utc()}

## Package

- Package ID: `{idx.get('package_id')}`
- Name: {idx.get('package_name')}
- Version: {idx.get('package_version')}
- Type: {idx.get('package_type')}
- Security status: {idx.get('security_status')}
- Artifacts using package: {len(idx.get('artifact_ids', []))}
- Vulnerabilities: {len(idx.get('vulnerability_ids', []))}
- Fixable findings: {idx.get('fixable_count')}

## Severity Summary

{severity_summary(idx.get('severity_counts'))}

## Vulnerabilities Affecting This Package

{list_lines(detail.get('vulnerabilities', []), lambda x: f"- **{x.get('highest_severity') or x.get('severity')}** `{x.get('vulnerability_id')}` - {x.get('security_status')}; fixed versions: {', '.join(x.get('fixed_versions', [])) or 'none known'}")}

## Artifacts Using This Package

{list_lines(detail.get('artifacts', []), lambda x: f"- `{(x.get('artifact') or {}).get('artifact_id')}` - findings: {x.get('finding_count')}; fixable: {x.get('fixable_count')}")}
"""

    def generate(self, report_type, target_id=None):
        if report_type == "org":
            return "org-security-report.md", self.org_report()
        if report_type == "remediation":
            return "remediation-report.md", self.remediation_report()
        if report_type == "artifact":
            return f"artifact-{safe_filename(target_id)}.md", self.artifact_report(target_id)
        if report_type == "vulnerability":
            return f"vulnerability-{safe_filename(target_id)}.md", self.vulnerability_report(target_id)
        if report_type == "package":
            return f"package-{safe_filename(target_id)}.md", self.package_report(target_id)
        raise ValueError(f"Unsupported report type: {report_type}")

    def write_report(self, report_type, target_id=None):
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        filename, content = self.generate(report_type, target_id)
        path = self.reports_dir / filename
        path.write_text(content, encoding="utf-8")
        return path