"""Query service for production org-data indexes.

Prepares display-ready data for the security console. The service uses production
indexes and manifests; templates should not know partition layout details.
"""

from datetime import datetime

SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1, "Unknown": 0}
SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
DEFAULT_PER_PAGE = 250


def severity_rank(value):
    return SEVERITY_ORDER.get(value or "Unknown", 0)


def empty_severity_counts():
    return {severity: 0 for severity in SEVERITIES}


def format_time(value):
    if not value:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y, %H:%M UTC")
    except Exception:
        return str(value)


def paginate(items, page=1, per_page=DEFAULT_PER_PAGE):
    page = max(int(page or 1), 1)
    per_page = max(int(per_page or DEFAULT_PER_PAGE), 1)
    total = len(items)
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = start + per_page
    return {"items": items[start:end], "page": page, "per_page": per_page, "total": total, "total_pages": total_pages, "has_prev": page > 1, "has_next": page < total_pages, "prev_page": page - 1, "next_page": page + 1, "start": start + 1 if total else 0, "end": min(end, total)}


class QueryService:
    """Provides dashboard/query methods on top of DataStore."""

    def __init__(self, store):
        self.store = store

    def overview(self):
        summary = self.store.index_summary or {}
        severity_totals = {**empty_severity_counts(), **(summary.get("severity_totals", {}) or {})}
        return {
            "run": self.store.run_metadata,
            "last_updated": format_time(summary.get("generated_at") or self.store.run_metadata.get("finished_at") or self.store.run_metadata.get("started_at")),
            "artifact_count": summary.get("artifact_count", len(self.store.by_artifact)),
            "package_count": summary.get("package_count", len(self.store.by_package)),
            "vulnerability_count": summary.get("vulnerability_count", len(self.store.by_vulnerability)),
            "finding_count": summary.get("finding_count", 0),
            "fixable_count": summary.get("fixable_count", 0),
            "not_fixable_count": summary.get("not_fixable_count", 0),
            "remediation_action_count": summary.get("remediation_count", len(self.store.remediation)),
            "critical_count": severity_totals.get("Critical", 0),
            "high_count": severity_totals.get("High", 0),
            "severity_totals": severity_totals,
            "error_count": len(self.store.run_errors),
            "warning_count": len(self.store.reference_warnings) + self.store.index_validation.get("warning_count", 0),
            "index_version": self.store.index_metadata.get("index_version"),
            "schema_version": self.store.index_metadata.get("schema_version"),
        }

    def remediation_items(self, severity=None, search=None):
        search_text = (search or "").lower().strip()
        items = []
        for item in self.store.remediation:
            if severity and item.get("highest_severity") != severity:
                continue
            haystack = item.get("search_text") or " ".join([item.get("vulnerability_id", ""), item.get("package_id", ""), " ".join(item.get("fixed_versions", []) or [])]).lower()
            if search_text and search_text not in haystack:
                continue
            items.append(item)
        return sorted(items, key=lambda x: (-severity_rank(x.get("highest_severity")), -x.get("affected_artifact_count", 0), x.get("vulnerability_id", "")))

    def _remediation_for_pair(self, vulnerability_id, package_id):
        return [item for item in self.store.remediation if item.get("vulnerability_id") == vulnerability_id and item.get("package_id") == package_id]

    def _fixed_versions_for_pair(self, vulnerability_id, package_id):
        versions = []
        for item in self._remediation_for_pair(vulnerability_id, package_id):
            for version in item.get("fixed_versions", []) or []:
                if version and version not in versions:
                    versions.append(version)
        return sorted(versions)

    def _affected_artifacts_for_pair(self, vulnerability_id, package_id, candidate_artifact_ids):
        affected = []
        for artifact_id in candidate_artifact_ids or []:
            for finding in self.store.artifact_findings(artifact_id):
                if finding.get("vulnerability_id") == vulnerability_id and finding.get("package_id") == package_id:
                    affected.append(artifact_id)
                    break
        return sorted(set(affected))

    def artifacts(self, search=None):
        search_text = (search or "").lower().strip()
        items = []
        for item in self.store.by_artifact.values():
            artifact = item.get("artifact") or {}
            haystack = item.get("search_text") or " ".join([item.get("canonical_id", ""), artifact.get("artifact_id", ""), artifact.get("artifact_type", ""), artifact.get("artifact_role", "")]).lower()
            if search_text and search_text not in haystack:
                continue
            items.append(item)
        return sorted(items, key=lambda x: (-x.get("critical_high_count", 0), not x.get("remediation_available", False), -x.get("finding_count", 0), (x.get("artifact") or {}).get("artifact_id", "")))

    def artifact_detail(self, id_or_route):
        summary = self.store.artifact_index(id_or_route)
        artifact_id = summary.get("canonical_id") or (summary.get("artifact") or {}).get("artifact_id") or self.store.resolver.canonical("artifacts", id_or_route)
        findings = self.store.artifact_findings(artifact_id)
        vulnerability_ids = sorted({item.get("vulnerability_id") for item in findings if item.get("vulnerability_id")})
        package_ids = sorted({item.get("package_id") for item in findings if item.get("package_id")})
        vulnerabilities = [self.store.vulnerability_index(vid) for vid in vulnerability_ids]
        packages = [self.package_detail(pid).get("index", {}) for pid in package_ids]
        vulnerabilities = [v for v in vulnerabilities if v]
        packages = [p for p in packages if p]
        vulnerabilities.sort(key=lambda x: (-severity_rank(x.get("highest_severity") or x.get("severity")), not x.get("remediation_available", False), x.get("vulnerability_id", "")))
        packages.sort(key=lambda x: (-x.get("critical_high_count", 0), not x.get("remediation_available", False), x.get("package_name", "")))
        return {"summary": summary, "artifact": (summary.get("artifact") or self.store.entities.get_artifact(artifact_id)), "project_ids": summary.get("project_ids", []), "vulnerabilities": vulnerabilities, "packages": packages}

    def vulnerabilities(self, severity=None, fix=None, search=None):
        search_text = (search or "").lower().strip()
        items = []
        for item in self.store.by_vulnerability:
            sev = item.get("highest_severity") or item.get("severity")
            if severity and sev != severity:
                continue
            if fix == "fixable" and not item.get("remediation_available"):
                continue
            if fix == "not-fixable" and item.get("remediation_available"):
                continue
            haystack = item.get("search_text") or " ".join([item.get("vulnerability_id", ""), sev or "", " ".join(item.get("aliases", []) or []), " ".join(item.get("cwes", []) or [])]).lower()
            if search_text and search_text not in haystack:
                continue
            items.append(item)
        return sorted(items, key=lambda x: (-severity_rank(x.get("highest_severity") or x.get("severity")), not x.get("remediation_available", False), -len(x.get("artifact_ids", [])), x.get("vulnerability_id", "")))

    def vulnerability_summary(self, items=None):
        items = items if items is not None else self.vulnerabilities()
        severity_counts = empty_severity_counts()
        fixable = mixed = not_fixable = 0
        for item in items:
            severity_counts[item.get("highest_severity") or item.get("severity") or "Unknown"] += 1
            status = item.get("security_status")
            if status == "Fixable":
                fixable += 1
            elif status == "Mixed":
                mixed += 1
            else:
                not_fixable += 1
        return {"total": len(items), "severity_counts": severity_counts, "fixable": fixable, "mixed": mixed, "not_fixable": not_fixable}

    def vulnerability_action_view(self, severity=None, fix=None, search=None, package_type=None):
        rows = []
        for vuln in self.vulnerabilities(severity=severity, search=search):
            vulnerability_id = vuln.get("vulnerability_id")
            entity = self.store.vulnerability_entity(vulnerability_id)
            description = entity.get("description") or ""
            for package_id in vuln.get("package_ids", []) or []:
                package = self.store.package_index(package_id)
                if not package:
                    continue
                if package_type and package.get("package_type") != package_type:
                    continue
                fixed_versions = self._fixed_versions_for_pair(vulnerability_id, package_id)
                row_fixable = bool(fixed_versions)
                if fix == "fixable" and not row_fixable:
                    continue
                if fix == "not-fixable" and row_fixable:
                    continue
                affected_artifacts = self._affected_artifacts_for_pair(vulnerability_id, package_id, vuln.get("artifact_ids", []))
                rows.append({
                    "vulnerability_id": vulnerability_id,
                    "vulnerability_route_id": vuln.get("route_id"),
                    "vulnerability_display_id": vuln.get("display_id") or vulnerability_id,
                    "severity": vuln.get("highest_severity") or vuln.get("severity"),
                    "description": description,
                    "package_id": package_id,
                    "package_route_id": package.get("route_id"),
                    "package_name": package.get("package_name"),
                    "package_version": package.get("package_version"),
                    "package_type": package.get("package_type"),
                    "fixed_versions": fixed_versions,
                    "fixable": row_fixable,
                    "affected_artifact_count": len(affected_artifacts),
                    "affected_artifact_ids": affected_artifacts,
                })
        rows.sort(key=lambda x: (-severity_rank(x.get("severity")), not x.get("fixable"), -x.get("affected_artifact_count", 0), x.get("vulnerability_id", ""), x.get("package_name", "")))
        return {"fixable": [r for r in rows if r["fixable"]], "not_fixable": [r for r in rows if not r["fixable"]], "all": rows}

    def vulnerability_detail(self, id_or_route):
        index_item = self.store.vulnerability_index(id_or_route)
        vulnerability_id = index_item.get("vulnerability_id") or self.store.resolver.canonical("vulnerabilities", id_or_route)
        entity = self.store.vulnerability_entity(vulnerability_id)
        packages = [self.package_detail(pid).get("index", {}) for pid in index_item.get("package_ids", [])]
        artifacts = [self.store.artifact_index(aid) for aid in index_item.get("artifact_ids", [])]
        packages = [p for p in packages if p]
        artifacts = [a for a in artifacts if a]
        packages.sort(key=lambda x: (not x.get("remediation_available", False), -len(x.get("artifact_ids", [])), x.get("package_name", "")))
        artifacts.sort(key=lambda x: (-x.get("fixable_count", 0), -x.get("finding_count", 0), (x.get("artifact") or {}).get("artifact_id", "")))
        return {"index": index_item, "entity": entity, "packages": packages, "artifacts": artifacts}

    def packages(self, package_type=None, search=None, status=None):
        search_text = (search or "").lower().strip()
        items = []
        for item in self.store.by_package:
            if package_type and item.get("package_type") != package_type:
                continue
            if status == "vulnerable" and item.get("finding_count", 0) <= 0:
                continue
            if status == "fixable" and not item.get("remediation_available"):
                continue
            if status == "clean" and item.get("finding_count", 0) > 0:
                continue
            haystack = item.get("search_text") or " ".join([item.get("package_id", ""), item.get("package_name", ""), item.get("package_version", ""), item.get("package_type", "")]).lower()
            if search_text and search_text not in haystack:
                continue
            items.append(item)
        return sorted(items, key=lambda x: (-x.get("critical_high_count", 0), not x.get("remediation_available", False), -x.get("finding_count", 0), x.get("package_type", ""), x.get("package_name", "")))

    def package_types(self):
        partitions = self.store.manifests.get("partitions", {}) or {}
        values = partitions.get("package_index_partitions")
        if isinstance(values, list):
            return values
        return sorted(set(item.get("package_type", "unknown") for item in self.store.by_package if item.get("package_type")))

    def package_detail(self, id_or_route):
        index_item = self.store.package_index(id_or_route)
        package_id = index_item.get("package_id") or self.store.resolver.canonical("packages", id_or_route)
        entity = self.store.package_entity(package_id)
        vulnerabilities = [self.store.vulnerability_index(vid) for vid in index_item.get("vulnerability_ids", [])]
        artifacts = [self.store.artifact_index(aid) for aid in index_item.get("artifact_ids", [])]
        vulnerabilities = [v for v in vulnerabilities if v]
        artifacts = [a for a in artifacts if a]
        if not index_item.get("licenses") and entity.get("licenses"):
            index_item = {**index_item, "licenses": entity.get("licenses", [])}
        vulnerabilities.sort(key=lambda x: (-severity_rank(x.get("highest_severity") or x.get("severity")), not x.get("remediation_available", False), x.get("vulnerability_id", "")))
        artifacts.sort(key=lambda x: (-x.get("fixable_count", 0), -x.get("finding_count", 0), (x.get("artifact") or {}).get("artifact_id", "")))
        return {"index": index_item, "entity": entity, "vulnerabilities": vulnerabilities, "artifacts": artifacts}

    def run_health(self):
        return {"errors": self.store.run_errors, "warnings": self.store.reference_warnings, "index_validation": self.store.index_validation, "index_metadata": self.store.index_metadata, "index_summary": self.store.index_summary}

    def paginate(self, items, page=1, per_page=DEFAULT_PER_PAGE):
        return paginate(items, page, per_page)