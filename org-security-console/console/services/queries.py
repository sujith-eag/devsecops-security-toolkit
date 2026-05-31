"""Reusable query service for UI pages and report generation."""

from datetime import datetime
from urllib.parse import unquote

SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1, "Unknown": 0}
SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]


def same_id(left, right):
    left = left or ""
    right = right or ""
    return left == right or unquote(left) == right or left == unquote(right) or unquote(left) == unquote(right)


def severity_rank(value):
    return SEVERITY_ORDER.get(value or "Unknown", 0)


def empty_severity_counts():
    return {severity: 0 for severity in SEVERITIES}


def fix_status(fixable_count, total_count, no_findings_label="No known vulnerabilities"):
    if total_count <= 0:
        return no_findings_label
    if fixable_count <= 0:
        return "Not fixable"
    if fixable_count == total_count:
        return "Fixable"
    return "Mixed"


def format_time(value):
    if not value:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y, %H:%M UTC")
    except Exception:
        return str(value)


class QueryService:
    """Provides display-ready dashboard/query methods on top of DataStore."""

    def __init__(self, store):
        self.store = store

    def _remediation_matches(self, vulnerability_id=None, package_id=None, artifact_id=None):
        matches = []
        for item in self.store.remediation:
            if vulnerability_id and item.get("vulnerability_id") != vulnerability_id:
                continue
            if package_id and not same_id(item.get("package_id"), package_id):
                continue
            if artifact_id and artifact_id not in item.get("affected_artifact_ids", []):
                continue
            matches.append(item)
        return matches

    def _fixed_versions_for(self, vulnerability_id=None, package_id=None, artifact_id=None):
        versions = []
        for item in self._remediation_matches(vulnerability_id, package_id, artifact_id):
            for version in item.get("fixed_versions", []) or []:
                if version and version not in versions:
                    versions.append(version)
        return versions

    def _package_index(self, package_id):
        package_id = package_id or ""
        item = next((item for item in self.store.by_package if same_id(item.get("package_id"), package_id)), {})
        total = item.get("finding_count", 0)
        fixable = item.get("fixable_count", 0)
        counts = item.get("severity_counts", {}) or empty_severity_counts()
        return {
            **item,
            "fix_status": fix_status(fixable, total),
            "critical_high_count": counts.get("Critical", 0) + counts.get("High", 0),
            "severity_counts": {**empty_severity_counts(), **counts},
            "has_vulnerabilities": total > 0,
            "has_fix": fixable > 0,
        }

    def _vulnerability_index(self, vulnerability_id):
        vulnerability_id = unquote(vulnerability_id or "")
        item = next((item for item in self.store.by_vulnerability if item.get("vulnerability_id") == vulnerability_id), {})
        total = item.get("finding_count", 0)
        fixable = item.get("fixable_count", 0)
        return {**item, "fix_status": fix_status(fixable, total, "Not fixable"), "has_fix": fixable > 0}

    def overview(self):
        artifacts = list(self.store.by_artifact.values())
        severity_totals = empty_severity_counts()
        for artifact in artifacts:
            for severity, count in artifact.get("severity_counts", {}).items():
                severity_totals[severity] = severity_totals.get(severity, 0) + count
        finding_count = sum(item.get("finding_count", 0) for item in artifacts)
        fixable_count = sum(item.get("fixable_count", 0) for item in artifacts)
        return {
            "run": self.store.run_metadata,
            "last_updated": format_time(self.store.run_metadata.get("finished_at") or self.store.run_metadata.get("started_at")),
            "artifact_count": len(artifacts),
            "package_count": self.store.run_metadata.get("package_count", len(self.store.by_package)),
            "vulnerability_count": self.store.run_metadata.get("vulnerability_count", len(self.store.by_vulnerability)),
            "finding_count": finding_count,
            "fixable_count": fixable_count,
            "not_fixable_count": max(finding_count - fixable_count, 0),
            "remediation_action_count": len(self.store.remediation),
            "critical_count": severity_totals.get("Critical", 0),
            "high_count": severity_totals.get("High", 0),
            "severity_totals": severity_totals,
            "error_count": len(self.store.run_errors),
            "warning_count": len(self.store.reference_warnings),
        }

    def remediation_items(self, severity=None):
        items = self.store.remediation
        if severity:
            items = [item for item in items if item.get("highest_severity") == severity]
        return sorted(items, key=lambda x: (-severity_rank(x.get("highest_severity")), -x.get("affected_artifact_count", 0), x.get("vulnerability_id", "")))

    def artifacts(self):
        items = []
        for item in self.store.by_artifact.values():
            counts = item.get("severity_counts", {}) or empty_severity_counts()
            total = item.get("finding_count", 0)
            fixable = item.get("fixable_count", 0)
            items.append({**item, "fix_status": fix_status(fixable, total), "critical_high_count": counts.get("Critical", 0) + counts.get("High", 0)})
        return sorted(items, key=lambda x: (-x.get("critical_high_count", 0), -x.get("fixable_count", 0), -x.get("finding_count", 0), (x.get("artifact") or {}).get("artifact_id", "")))

    def artifact_detail(self, artifact_id):
        artifact_id = unquote(artifact_id or "")
        summary = self.store.artifact_index(artifact_id)
        findings = self.store.artifact_findings(artifact_id)
        vulnerability_ids = sorted({item.get("vulnerability_id") for item in findings if item.get("vulnerability_id")})
        package_ids = sorted({item.get("package_id") for item in findings if item.get("package_id")})
        vulnerabilities = [self._vulnerability_index(vid) for vid in vulnerability_ids]
        packages = [self._package_index(pid) for pid in package_ids]
        for vuln in vulnerabilities:
            vuln["fixed_versions"] = self._fixed_versions_for(vulnerability_id=vuln.get("vulnerability_id"), artifact_id=artifact_id)
        for pkg in packages:
            pkg["fixed_versions"] = self._fixed_versions_for(package_id=pkg.get("package_id"), artifact_id=artifact_id)
        vulnerabilities.sort(key=lambda x: (-severity_rank(x.get("severity")), not x.get("has_fix"), x.get("vulnerability_id", "")))
        packages.sort(key=lambda x: (-x.get("critical_high_count", 0), not x.get("has_fix"), x.get("package_name", "")))
        return {
            "summary": summary,
            "artifact": (summary.get("artifact") or self.store.entities.get_artifact(artifact_id)),
            "project_ids": summary.get("project_ids", []),
            "vulnerabilities": vulnerabilities,
            "packages": packages,
        }

    def vulnerabilities(self, severity=None, fix=None):
        items = []
        for item in self.store.by_vulnerability:
            enriched = self._vulnerability_index(item.get("vulnerability_id"))
            if severity and enriched.get("severity") != severity:
                continue
            if fix == "fixable" and enriched.get("fixable_count", 0) <= 0:
                continue
            if fix == "not-fixable" and enriched.get("fixable_count", 0) > 0:
                continue
            items.append(enriched)
        return sorted(items, key=lambda x: (-severity_rank(x.get("severity")), not x.get("has_fix"), -len(x.get("artifact_ids", [])), x.get("vulnerability_id", "")))

    def vulnerability_summary(self, items=None):
        items = items if items is not None else self.vulnerabilities()
        severity_counts = empty_severity_counts()
        fixable = mixed = not_fixable = 0
        for item in items:
            severity_counts[item.get("severity") or "Unknown"] += 1
            status = item.get("fix_status")
            if status == "Fixable":
                fixable += 1
            elif status == "Mixed":
                mixed += 1
            else:
                not_fixable += 1
        return {"total": len(items), "severity_counts": severity_counts, "fixable": fixable, "mixed": mixed, "not_fixable": not_fixable}

    def vulnerability_detail(self, vulnerability_id):
        vulnerability_id = unquote(vulnerability_id or "")
        index_item = self._vulnerability_index(vulnerability_id)
        entity = self.store.entities.get_vulnerability(vulnerability_id)
        packages = [self._package_index(pid) for pid in index_item.get("package_ids", [])]
        artifacts = [self.store.artifact_index(aid) for aid in index_item.get("artifact_ids", [])]
        for pkg in packages:
            pkg["fixed_versions"] = self._fixed_versions_for(vulnerability_id=vulnerability_id, package_id=pkg.get("package_id"))
        packages = [p for p in packages if p.get("package_id")]
        packages.sort(key=lambda x: (not x.get("fixed_versions"), -len(x.get("artifact_ids", [])), x.get("package_name", "")))
        artifacts.sort(key=lambda x: (-x.get("fixable_count", 0), -x.get("finding_count", 0), (x.get("artifact") or {}).get("artifact_id", "")))
        return {"index": index_item, "entity": entity, "packages": packages, "artifacts": [a for a in artifacts if a]}

    def packages(self, package_type=None, search=None, status=None):
        items = []
        search_text = (search or "").lower().strip()
        for item in self.store.by_package:
            enriched = self._package_index(item.get("package_id"))
            if not enriched.get("package_id"):
                continue
            if package_type and enriched.get("package_type") != package_type:
                continue
            if status == "vulnerable" and not enriched.get("has_vulnerabilities"):
                continue
            if status == "fixable" and not enriched.get("has_fix"):
                continue
            if status == "clean" and enriched.get("has_vulnerabilities"):
                continue
            haystack = " ".join([enriched.get("package_id", ""), enriched.get("package_name", ""), enriched.get("package_version", ""), enriched.get("package_type", "")]).lower()
            if search_text and search_text not in haystack:
                continue
            items.append(enriched)
        return sorted(items, key=lambda x: (-x.get("critical_high_count", 0), not x.get("has_fix"), -x.get("finding_count", 0), x.get("package_type", ""), x.get("package_name", "")))

    def package_types(self):
        return sorted(set(item.get("package_type", "unknown") for item in self.store.by_package if item.get("package_type")))

    def package_detail(self, package_id):
        package_id = package_id or ""
        index_item = self._package_index(package_id)
        entity = self.store.entities.get_package(package_id)
        vulnerabilities = [self._vulnerability_index(vid) for vid in index_item.get("vulnerability_ids", [])]
        artifacts = [self.store.artifact_index(aid) for aid in index_item.get("artifact_ids", [])]
        for vuln in vulnerabilities:
            vuln["fixed_versions"] = self._fixed_versions_for(vulnerability_id=vuln.get("vulnerability_id"), package_id=package_id)
        vulnerabilities = [v for v in vulnerabilities if v.get("vulnerability_id")]
        vulnerabilities.sort(key=lambda x: (-severity_rank(x.get("severity")), not x.get("fixed_versions"), x.get("vulnerability_id", "")))
        artifacts.sort(key=lambda x: (-x.get("fixable_count", 0), -x.get("finding_count", 0), (x.get("artifact") or {}).get("artifact_id", "")))
        return {"index": index_item, "entity": entity, "vulnerabilities": vulnerabilities, "artifacts": [a for a in artifacts if a]}

    def run_health(self):
        return {"errors": self.store.run_errors, "warnings": self.store.reference_warnings}