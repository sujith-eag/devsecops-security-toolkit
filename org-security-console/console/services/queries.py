"""Reusable query service for UI pages and report generation."""

from urllib.parse import unquote

SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1, "Unknown": 0}


def severity_rank(value):
    return SEVERITY_ORDER.get(value or "Unknown", 0)


class QueryService:
    """Provides dashboard/query methods on top of DataStore."""

    def __init__(self, store):
        self.store = store

    def overview(self):
        artifacts = list(self.store.by_artifact.values())
        severity_totals = {key: 0 for key in SEVERITY_ORDER}
        for artifact in artifacts:
            for severity, count in artifact.get("severity_counts", {}).items():
                severity_totals[severity] = severity_totals.get(severity, 0) + count
        return {
            "run": self.store.run_metadata,
            "index_metadata": self.store.index_metadata,
            "artifact_count": len(artifacts),
            "package_count": self.store.run_metadata.get("package_count", len(self.store.by_package)),
            "vulnerability_count": self.store.run_metadata.get("vulnerability_count", len(self.store.by_vulnerability)),
            "remediation_count": len(self.store.remediation),
            "finding_count": sum(item.get("finding_count", 0) for item in artifacts),
            "fixable_count": sum(item.get("fixable_count", 0) for item in artifacts),
            "severity_totals": severity_totals,
            "error_count": len(self.store.run_errors),
            "warning_count": len(self.store.reference_warnings),
        }

    def remediation_items(self):
        return sorted(
            self.store.remediation,
            key=lambda x: (-severity_rank(x.get("highest_severity")), -x.get("affected_artifact_count", 0), x.get("vulnerability_id", "")),
        )

    def artifacts(self):
        return sorted(
            self.store.by_artifact.values(),
            key=lambda x: (-x.get("finding_count", 0), (x.get("artifact") or {}).get("artifact_id", "")),
        )

    def artifact_detail(self, artifact_id):
        artifact_id = unquote(artifact_id or "")
        summary = self.store.artifact_index(artifact_id)
        return {
            "summary": summary,
            "artifact": (summary.get("artifact") or self.store.entities.get_artifact(artifact_id)),
            "project_ids": summary.get("project_ids", []),
        }

    def vulnerabilities(self):
        return sorted(
            self.store.by_vulnerability,
            key=lambda x: (-severity_rank(x.get("severity")), -x.get("finding_count", 0), x.get("vulnerability_id", "")),
        )

    def vulnerability_detail(self, vulnerability_id):
        vulnerability_id = unquote(vulnerability_id or "")
        index_item = next((item for item in self.store.by_vulnerability if item.get("vulnerability_id") == vulnerability_id), {})
        entity = self.store.entities.get_vulnerability(vulnerability_id)
        return {"index": index_item, "entity": entity}

    def packages(self):
        return sorted(
            self.store.by_package,
            key=lambda x: (-x.get("finding_count", 0), x.get("package_type", ""), x.get("package_name", "")),
        )

    def package_detail(self, package_id):
        package_id = unquote(package_id or "")
        index_item = next((item for item in self.store.by_package if item.get("package_id") == package_id), {})
        entity = self.store.entities.get_package(package_id)
        return {"index": index_item, "entity": entity}

    def run_health(self):
        return {"errors": self.store.run_errors, "warnings": self.store.reference_warnings}
