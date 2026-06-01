"""Build vulnerability entities and finding relationships from Grype SBOM output.

This module normalizes Grype vulnerability IDs into a canonical vulnerability
identity. Where a GHSA/advisory clearly maps to one CVE through EPSS/CWE data or
related vulnerability IDs, the CVE is used as the canonical vulnerability ID.
The original Grype ID is preserved as source/alias metadata.
"""

from orgdata.normalize.ids import finding_id, normalize_package_type, package_id_from_values
from orgdata.normalize.severity import SEVERITIES, empty_severity_counts, highest_severity, normalize_severity
from orgdata.vulnerabilities.parser import grype_matches


def as_list(value):
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def merge_unique(existing, values):
    merged = list(existing or [])
    for value in as_list(values):
        if value not in (None, "") and value not in merged:
            merged.append(value)
    return merged


def id_type(value):
    value = str(value or "")
    if value.startswith("CVE-"):
        return "CVE"
    if value.startswith("GHSA-"):
        return "GHSA"
    return "other"


def unique_cves(values):
    return sorted({str(value) for value in values if str(value).startswith("CVE-")})


def cve_from_epss_cwes(vulnerability):
    candidates = []
    for item in vulnerability.get("epss") or []:
        if isinstance(item, dict) and item.get("cve"):
            candidates.append(item.get("cve"))
    for item in vulnerability.get("cwes") or []:
        if isinstance(item, dict) and item.get("cve"):
            candidates.append(item.get("cve"))
    cves = unique_cves(candidates)
    return cves[0] if len(cves) == 1 else ""


def cve_from_related(match):
    candidates = []
    for item in match.get("relatedVulnerabilities") or []:
        if isinstance(item, dict) and item.get("id"):
            candidates.append(item.get("id"))
    cves = unique_cves(candidates)
    return cves[0] if len(cves) == 1 else ""


def related_ids(match):
    ids = []
    for item in match.get("relatedVulnerabilities") or []:
        if isinstance(item, dict) and item.get("id"):
            ids.append(item.get("id"))
    return sorted(set(ids))


def vulnerability_identity(match):
    vuln = match.get("vulnerability") or {}
    primary_id = str(vuln.get("id") or "")

    if primary_id.startswith("CVE-"):
        canonical_id = primary_id
    else:
        canonical_id = cve_from_epss_cwes(vuln) or cve_from_related(match) or primary_id

    all_ids = merge_unique([primary_id], related_ids(match))
    aliases = sorted([item for item in all_ids if item and item != canonical_id])

    return {
        "canonical_vulnerability_id": canonical_id,
        "source_vulnerability_id": primary_id if primary_id != canonical_id else "",
        "aliases": aliases,
    }


def fix_versions(vulnerability):
    versions = (vulnerability.get("fix") or {}).get("versions") or []
    return sorted(str(v) for v in versions if v not in (None, ""))


def fix_observed(vulnerability):
    available = (vulnerability.get("fix") or {}).get("available") or []
    first_observed = [item for item in available if isinstance(item, dict) and item.get("kind") == "first-observed"]
    candidates = first_observed or [item for item in available if isinstance(item, dict)]
    if not candidates:
        return None
    selected = sorted(candidates, key=lambda x: str(x.get("date", "")))[0]
    return {
        "version": selected.get("version", ""),
        "date": selected.get("date", ""),
        "kind": selected.get("kind", ""),
    }


def match_types(match):
    return sorted(set(str(detail.get("type")) for detail in (match.get("matchDetails") or []) if isinstance(detail, dict) and detail.get("type")))


def cwes(vulnerability):
    result = []
    for item in vulnerability.get("cwes") or []:
        if isinstance(item, dict) and item.get("cwe") and item.get("cwe") not in result:
            result.append(item.get("cwe"))
    return result


def cvss(vulnerability):
    result = []
    for item in vulnerability.get("cvss") or []:
        if not isinstance(item, dict):
            continue
        metrics = item.get("metrics") or {}
        result.append({
            "source": item.get("source", ""),
            "type": item.get("type", ""),
            "version": item.get("version", ""),
            "vector": item.get("vector", ""),
            "base_score": metrics.get("baseScore"),
            "exploitability_score": metrics.get("exploitabilityScore"),
            "impact_score": metrics.get("impactScore"),
        })
    return result


def cvss_summary(cvss_items):
    valid = [item for item in cvss_items or [] if item.get("base_score") is not None]
    if not valid:
        return None
    selected = sorted(valid, key=lambda x: float(x.get("base_score") or 0), reverse=True)[0]
    return {
        "base_score": selected.get("base_score"),
        "exploitability_score": selected.get("exploitability_score"),
        "impact_score": selected.get("impact_score"),
        "version": selected.get("version", ""),
        "vector": selected.get("vector", ""),
        "source": selected.get("source", ""),
        "type": selected.get("type", ""),
    }


def epss(vulnerability):
    values = vulnerability.get("epss") or []
    if not values:
        return None
    latest = sorted(values, key=lambda x: x.get("date", ""), reverse=True)[0]
    return {
        "score": latest.get("epss"),
        "percentile": latest.get("percentile"),
        "date": latest.get("date"),
    }


def vulnerability_bucket(vulnerability_id):
    text = vulnerability_id or "other"
    if text.startswith("CVE-"):
        parts = text.split("-")
        return f"CVE-{parts[1]}" if len(parts) > 1 and parts[1].isdigit() else "CVE-other"
    if text.startswith("GHSA-"):
        return "GHSA"
    return "other"

def build_vulnerability(match):
    vuln = match.get("vulnerability") or {}
    identity = vulnerability_identity(match)
    cvss_items = cvss(vuln)
    risk = vuln.get("risk")

    return {
        "vulnerability_id": identity["canonical_vulnerability_id"],
        "source_vulnerability_id": identity["source_vulnerability_id"],
        "aliases": identity["aliases"],
        "severity": normalize_severity(vuln.get("severity")),
        "namespaces": as_list(vuln.get("namespace")),
        "data_sources": as_list(vuln.get("dataSource")),
        "description": vuln.get("description", ""),
        "urls": merge_unique([], vuln.get("urls") or []),
        "cwes": cwes(vuln),
        "cvss_summary": cvss_summary(cvss_items),
        "epss": epss(vuln),
        "risk_score": round(float(risk), 6) if risk is not None else None,
        "fix_observed": fix_observed(vuln),
    }


def merge_cvss(existing, values):
    merged = list(existing or [])
    seen = {"|".join([str(i.get("source", "")), str(i.get("type", "")), str(i.get("version", "")), str(i.get("vector", ""))]) for i in merged if isinstance(i, dict)}
    for item in values or []:
        if not isinstance(item, dict):
            continue
        key = "|".join([str(item.get("source", "")), str(item.get("type", "")), str(item.get("version", "")), str(item.get("vector", ""))])
        if key not in seen:
            seen.add(key)
            merged.append(item)
    return merged


def latest_epss(existing, new):
    if not existing:
        return new
    if not new:
        return existing
    return new if str(new.get("date", "")) > str(existing.get("date", "")) else existing


def better_cvss_summary(existing, new):
    if not existing:
        return new
    if not new:
        return existing
    return new if float(new.get("base_score") or 0) > float(existing.get("base_score") or 0) else existing


def merge_vulnerability(existing, new):
    existing["severity"] = highest_severity([existing.get("severity"), new.get("severity")])
    existing["aliases"] = merge_unique(existing.get("aliases"), new.get("aliases"))
    existing["namespaces"] = merge_unique(existing.get("namespaces"), new.get("namespaces"))
    existing["data_sources"] = merge_unique(existing.get("data_sources"), new.get("data_sources"))
    existing["urls"] = merge_unique(existing.get("urls"), new.get("urls"))
    existing["cwes"] = merge_unique(existing.get("cwes"), new.get("cwes"))
    existing["cvss_summary"] = better_cvss_summary(existing.get("cvss_summary"), new.get("cvss_summary"))
    if not existing.get("description") and new.get("description"):
        existing["description"] = new.get("description")
    existing["epss"] = latest_epss(existing.get("epss"), new.get("epss"))
    if not existing.get("fix_observed") and new.get("fix_observed"):
        existing["fix_observed"] = new.get("fix_observed")
    if existing.get("risk_score") is None:
        existing["risk_score"] = new.get("risk_score")
    elif new.get("risk_score") is not None:
        existing["risk_score"] = max(existing.get("risk_score"), new.get("risk_score"))
    existing["source_vulnerability_id"] = existing.get("source_vulnerability_id") or new.get("source_vulnerability_id")
    return existing


def build_finding(match, artifact_id):
    vuln = match.get("vulnerability") or {}
    identity = vulnerability_identity(match)
    artifact = match.get("artifact") or {}
    vulnerability_id = identity["canonical_vulnerability_id"]
    package_type = normalize_package_type(artifact.get("type") or "")
    package_name = str(artifact.get("name") or "")
    package_version = str(artifact.get("version") or "")
    package_purl = str(artifact.get("purl") or "")
    package_id = package_id_from_values(package_purl, package_type, package_name, package_version)
    fixed_versions = fix_versions(vuln)
    fix_state = str((vuln.get("fix") or {}).get("state") or "unknown")

    return {
        "finding_id": finding_id(artifact_id, vulnerability_id, package_id),
        "artifact_id": artifact_id,
        "package_id": package_id,
        "vulnerability_id": vulnerability_id,
        "source_vulnerability_id": identity["source_vulnerability_id"],
        "vulnerability_aliases": identity["aliases"],
        "severity": normalize_severity(vuln.get("severity")),
        "fix_state": fix_state,
        "fix_available": bool(fixed_versions),
        "fixed_versions": fixed_versions,
        "match_types": match_types(match),
        "duplicate_count": 1,
    }


def merge_finding(existing, new):
    existing["severity"] = highest_severity([existing.get("severity"), new.get("severity")])
    existing["fixed_versions"] = sorted(merge_unique(existing.get("fixed_versions"), new.get("fixed_versions")))
    existing["fix_available"] = bool(existing["fixed_versions"])
    if existing.get("fix_state") != "fixed" and new.get("fix_state") == "fixed":
        existing["fix_state"] = "fixed"
    existing["match_types"] = sorted(merge_unique(existing.get("match_types"), new.get("match_types")))
    existing["vulnerability_aliases"] = sorted(merge_unique(existing.get("vulnerability_aliases"), new.get("vulnerability_aliases")))
    existing["duplicate_count"] = existing.get("duplicate_count", 1) + new.get("duplicate_count", 1)
    return existing


def build_vulnerability_records(artifact_id, grype_data):
    vulnerabilities = {}
    findings = {}

    for match in grype_matches(grype_data):
        vulnerability = build_vulnerability(match)
        if vulnerability.get("vulnerability_id"):
            key = vulnerability["vulnerability_id"]
            vulnerabilities[key] = merge_vulnerability(vulnerabilities[key], vulnerability) if key in vulnerabilities else vulnerability

        finding = build_finding(match, artifact_id)
        if finding.get("finding_id") and finding.get("package_id") and finding.get("vulnerability_id"):
            key = finding["finding_id"]
            findings[key] = merge_finding(findings[key], finding) if key in findings else finding

    return list(vulnerabilities.values()), list(findings.values())


def compare_findings(old_findings, new_findings):
    old_by_id = {item["finding_id"]: item for item in old_findings}
    new_by_id = {item["finding_id"]: item for item in new_findings}
    new_items = [new_by_id[key] for key in sorted(set(new_by_id) - set(old_by_id))]
    changed = []

    for key in sorted(set(old_by_id) & set(new_by_id)):
        old = old_by_id[key]
        new = new_by_id[key]
        changes = {}
        for field in ("severity", "fix_state", "fixed_versions"):
            if old.get(field) != new.get(field):
                changes[field] = {"old": old.get(field), "new": new.get(field)}
        if changes:
            changed.append({"finding_id": key, "artifact_id": new.get("artifact_id"), "package_id": new.get("package_id"), "vulnerability_id": new.get("vulnerability_id"), "changes": changes})

    return {"new": new_items, "changed": changed}


def group_findings_by_fixability_and_severity(artifact_id, findings):
    grouped = {
        "artifact_id": artifact_id,
        "finding_count": len(findings),
        "fixable_count": 0,
        "not_fixable_count": 0,
        "severity_counts": empty_severity_counts(),
        "findings": {
            "fixable": {severity: [] for severity in SEVERITIES},
            "not_fixable": {severity: [] for severity in SEVERITIES},
        },
    }
    for finding in sorted(findings, key=lambda x: x.get("finding_id", "")):
        severity = normalize_severity(finding.get("severity"))
        bucket = "fixable" if finding.get("fix_available") else "not_fixable"
        grouped["severity_counts"][severity] += 1
        grouped["fixable_count" if bucket == "fixable" else "not_fixable_count"] += 1
        grouped["findings"][bucket][severity].append(finding)
    return grouped