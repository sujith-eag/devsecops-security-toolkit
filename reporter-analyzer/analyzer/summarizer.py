from collections import Counter


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]


def normalized_severity(severity):
    if not severity:
        return "Unknown"
    value = severity.lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "negligible": "Negligible",
        "unknown": "Unknown",
    }.get(value, severity.capitalize())


def top_items(counter, limit=10):
    return [{"name": name, "count": count} for name, count in counter.most_common(limit)]


def severity_rank(severity):
    normalized = normalized_severity(severity)
    return SEVERITY_ORDER.index(normalized) if normalized in SEVERITY_ORDER else 99


def merge_unique(values):
    result = []
    for value in values:
        if isinstance(value, list):
            for item in value:
                if item and item not in result:
                    result.append(item)
        elif value and value not in result:
            result.append(value)
    return result


def build_cve_groups(records):
    groups = {}

    for record in records:
        cve = record.get("vulnerability_id") or "UNKNOWN"

        if cve not in groups:
            groups[cve] = {
                "vulnerability_id": cve,
                "severity": normalized_severity(record.get("severity")),
                "affected_packages": [],
                "package_types": [],
                "fixed_versions": [],
                "fix_available": False,
                "remediation_areas": [],
                "remediation_actions": [],
                "finding_count": 0,
            }

        group = groups[cve]
        group["finding_count"] += 1

        current_severity = normalized_severity(record.get("severity"))
        if severity_rank(current_severity) < severity_rank(group["severity"]):
            group["severity"] = current_severity

        package_label = f"{record.get('package_name')}@{record.get('package_version')}"
        group["affected_packages"] = merge_unique([group["affected_packages"], package_label])
        group["package_types"] = merge_unique([group["package_types"], record.get("package_type")])
        group["fixed_versions"] = merge_unique([group["fixed_versions"], record.get("fixed_versions", [])])
        group["remediation_areas"] = merge_unique([group["remediation_areas"], record.get("remediation_area")])
        group["remediation_actions"] = merge_unique([group["remediation_actions"], record.get("remediation_action")])

        if record.get("fix_available"):
            group["fix_available"] = True

    return sorted(
        groups.values(),
        key=lambda g: (severity_rank(g.get("severity")), g.get("vulnerability_id", ""))
    )

def build_summary(metadata, records, sbom, warnings, generated_at, raw_match_count):
    severity_counter = Counter(normalized_severity(r.get("severity")) for r in records)
    package_counter = Counter(r.get("package_name") or "unknown" for r in records)
    remediation_counter = Counter(r.get("remediation_area") or "unknown" for r in records)

    priority_findings = [
        r for r in records
        if normalized_severity(r.get("severity")) in {"Critical", "High"}
    ]

    priority_findings = sorted(
        priority_findings,
        key=lambda r: severity_rank(r.get("severity"))
    )

    cve_groups = build_cve_groups(records)
    priority_cve_groups = [
        group for group in cve_groups
        if group.get("severity") in {"Critical", "High"}
    ]

    return {
        "generated_at": generated_at,
        "schema_version": metadata.get("schema_version", "1.0"),
        "artifact": {
            "artifact_id": metadata.get("artifact_id", ""),
            "artifact_type": metadata.get("artifact_type", ""),
            "artifact_role": metadata.get("artifact_role", ""),
        },
        "project": metadata.get("project", {}),
        "image": metadata.get("image", {}),
        "scan": metadata.get("scan", {}),
        "summary": {
            "raw_match_count": raw_match_count,
            "unique_finding_count": len(records),
            "duplicates_reduced": max(raw_match_count - len(records), 0),
            "total_findings": len(records),
            "severity_counts": {severity: severity_counter.get(severity, 0) for severity in SEVERITY_ORDER},
            "fixable_findings": sum(1 for r in records if r.get("fix_available")),
            "non_fixable_findings": sum(1 for r in records if not r.get("fix_available")),
            "sbom_component_count": len(sbom.get("components", [])) if sbom else None,
        },
        "top_affected_packages": top_items(package_counter),
        "remediation_area_counts": dict(remediation_counter),
        "priority_findings": priority_findings,
        "cve_groups": cve_groups,
        "priority_cve_groups": priority_cve_groups,
        "warnings": warnings,
    }
