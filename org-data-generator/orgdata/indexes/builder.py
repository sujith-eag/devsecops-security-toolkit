"""Production index builder for normalized org-data.

Builds query-friendly, partitioned, enveloped indexes from normalized entities
and relationships. The implementation remains partition-aware and avoids holding
large package/vulnerability partitions in memory at the same time.
"""

from pathlib import Path

from orgdata.indexes.ids import id_fields
from orgdata.indexes.loader import (
    artifact_package_files,
    finding_files,
    load_artifact_packages,
    load_artifacts,
    load_findings,
    load_json_records,
    load_project_artifacts,
    package_partition_files,
    vulnerability_partition_files,
)
from orgdata.indexes.writer import (
    INDEX_VERSION,
    SCHEMA_VERSION,
    reset_indexes,
    utc_now,
    write_artifact_index,
    write_index_metadata,
    write_index_summary,
    write_index_validation,
    write_manifest,
    write_package_index_partition,
    write_remediation_index,
    write_vulnerability_index_partition,
)
from orgdata.normalize.severity import empty_severity_counts, highest_severity, normalize_severity, severity_rank


def add_unique(target, value):
    if value not in (None, "") and value not in target:
        target.append(value)


def sorted_unique(values):
    return sorted(v for v in set(values or []) if v not in (None, ""))


def project_ids_for(artifact_projects, artifact_id):
    return sorted(artifact_projects.get(artifact_id, set()))


def security_status(fixable_count, total_count):
    if total_count <= 0:
        return "No known vulnerabilities"
    if fixable_count <= 0:
        return "Not fixable"
    if fixable_count == total_count:
        return "Fixable"
    return "Mixed"


def compact_artifact(artifact):
    artifact_id = artifact.get("artifact_id", "")
    return {**id_fields(artifact_id, "artifact"), "artifact_id": artifact_id, "artifact_folder": artifact.get("artifact_folder", ""), "artifact_type": artifact.get("artifact_type", ""), "artifact_role": artifact.get("artifact_role", ""), "project_id": artifact.get("project_id", ""), "image": artifact.get("image", {}), "source": artifact.get("source", {})}


def compact_package(package):
    package_id = package.get("package_id", "")
    return {**id_fields(package_id, "package"), "package_id": package_id, "package_name": package.get("package_name", ""), "package_version": package.get("package_version", ""), "package_type": package.get("package_type", ""), "package_group": package.get("package_group", ""), "normalized_purl": package.get("normalized_purl", ""), "licenses": package.get("licenses", []), "search_text": " ".join([package_id, package.get("package_name", ""), package.get("package_version", ""), package.get("package_type", ""), " ".join(package.get("licenses", []) or [])]).lower(), "labels": sorted_unique([package.get("package_type"), package.get("package_group"), *(package.get("licenses", []) or [])])}


def compact_vulnerability(vulnerability):
    vulnerability_id = vulnerability.get("vulnerability_id", "")
    return {
        **id_fields(vulnerability_id, "vulnerability"),
        "vulnerability_id": vulnerability_id,
        "source_vulnerability_id": vulnerability.get("source_vulnerability_id", ""),
        "aliases": vulnerability.get("aliases", []),
        "severity": vulnerability.get("severity", "Unknown"),
        "namespaces": vulnerability.get("namespaces", []),
        "data_sources": vulnerability.get("data_sources", []),
        "urls": vulnerability.get("urls", []),
        "cwes": vulnerability.get("cwes", []),
        "cvss_summary": vulnerability.get("cvss_summary"),
        "epss": vulnerability.get("epss"),
        "risk_score": vulnerability.get("risk_score"),
        "fix_observed": vulnerability.get("fix_observed"),
        "search_text": " ".join([
            vulnerability_id,
            " ".join(vulnerability.get("aliases", []) or []),
            vulnerability.get("severity", ""),
            " ".join(vulnerability.get("cwes", []) or []),
        ]).lower(),
        "labels": sorted_unique([
            vulnerability.get("severity"),
            *(vulnerability.get("cwes", []) or []),
        ]),
    }

def collect_findings_by_artifact(current_dir):
    result = {}
    for path in finding_files(current_dir):
        artifact_id, findings = load_findings(path)
        if artifact_id:
            result[artifact_id] = findings
    return result


def collect_artifact_packages_by_artifact(current_dir):
    result = {}
    for path in artifact_package_files(current_dir):
        artifact_id, packages = load_artifact_packages(path)
        if artifact_id:
            result[artifact_id] = packages
    return result


def finding_stats(findings):
    severity_counts = empty_severity_counts()
    fixed_versions = []
    vulnerability_ids = []
    package_ids = []
    artifact_ids = []
    fixable_count = 0
    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        severity_counts[severity] += 1
        if finding.get("fix_available"):
            fixable_count += 1
        for version in finding.get("fixed_versions", []) or []:
            add_unique(fixed_versions, version)
        add_unique(vulnerability_ids, finding.get("vulnerability_id"))
        add_unique(package_ids, finding.get("package_id"))
        add_unique(artifact_ids, finding.get("artifact_id"))
    highest = "Unknown"
    for severity, count in severity_counts.items():
        if count and severity_rank(severity) > severity_rank(highest):
            highest = severity
    return {"finding_count": len(findings), "fixable_count": fixable_count, "not_fixable_count": max(len(findings) - fixable_count, 0), "security_status": security_status(fixable_count, len(findings)), "remediation_available": fixable_count > 0, "fixed_versions": sorted(fixed_versions), "severity_counts": severity_counts, "highest_severity": highest, "critical_high_count": severity_counts.get("Critical", 0) + severity_counts.get("High", 0), "vulnerability_ids": sorted(vulnerability_ids), "package_ids": sorted(package_ids), "artifact_ids": sorted(artifact_ids)}

# The rest of the builder keeps the production partition flow but uses the enriched compact records above.
# To avoid changing flow, import the previous logic dynamically is not appropriate here, so below are the core build functions.

def build_by_artifact(current_dir, artifacts, artifact_projects, manifests, summary):
    artifact_packages = collect_artifact_packages_by_artifact(current_dir)
    findings_by_artifact = collect_findings_by_artifact(current_dir)
    written = 0
    for artifact_id, artifact in artifacts.items():
        package_links = artifact_packages.get(artifact_id, [])
        findings = findings_by_artifact.get(artifact_id, [])
        stats = finding_stats(findings)
        package_ids = sorted_unique([item.get("package_id") for item in package_links])
        record = {**id_fields(artifact_id, "artifact-index"), "artifact": compact_artifact(artifact), "project_ids": project_ids_for(artifact_projects, artifact_id), "package_count": len(package_ids), "vulnerable_package_count": len(stats["package_ids"]), "package_ids": package_ids, "vulnerable_package_ids": stats["package_ids"], **{k: v for k, v in stats.items() if k not in ("package_ids", "artifact_ids")}, "search_text": " ".join([artifact_id, artifact.get("artifact_type", ""), artifact.get("artifact_role", "")]).lower(), "labels": sorted_unique([artifact.get("artifact_type"), artifact.get("artifact_role")])}
        write_artifact_index(current_dir, artifact_id, record)
        manifests["artifacts"][artifact_id] = {**id_fields(artifact_id, "artifact"), "partition": f"indexes/by-artifact/{artifact_id}.json", "artifact_type": artifact.get("artifact_type", ""), "artifact_role": artifact.get("artifact_role", ""), "project_ids": record["project_ids"]}
        summary["artifact_count"] += 1
        summary["finding_count"] += stats["finding_count"]
        summary["fixable_count"] += stats["fixable_count"]
        summary["not_fixable_count"] += stats["not_fixable_count"]
        for severity, count in stats["severity_counts"].items():
            summary["severity_totals"][severity] += count
        written += 1
    return written


def build_by_package(current_dir, artifact_projects, manifests, summary):
    written_partitions = 0
    artifact_package_files_list = artifact_package_files(current_dir)
    finding_files_list = finding_files(current_dir)
    for package_file in package_partition_files(current_dir):
        packages = {item.get("package_id"): compact_package(item) for item in load_json_records(package_file) if item.get("package_id")}
        index = {package_id: {**package, "artifact_ids": [], "project_ids": [], "vulnerability_ids": [], "finding_count": 0, "fixable_count": 0, "not_fixable_count": 0, "security_status": "No known vulnerabilities", "remediation_available": False, "fixed_versions": [], "severity_counts": empty_severity_counts(), "highest_severity": "Unknown", "critical_high_count": 0} for package_id, package in packages.items()}
        for rel_file in artifact_package_files_list:
            artifact_id, package_links = load_artifact_packages(rel_file)
            for link in package_links:
                package_id = link.get("package_id")
                if package_id in index:
                    add_unique(index[package_id]["artifact_ids"], artifact_id)
                    for project_id in project_ids_for(artifact_projects, artifact_id):
                        add_unique(index[package_id]["project_ids"], project_id)
        for findings_file in finding_files_list:
            artifact_id, findings = load_findings(findings_file)
            for finding in findings:
                package_id = finding.get("package_id")
                if package_id not in index:
                    continue
                item = index[package_id]
                add_unique(item["vulnerability_ids"], finding.get("vulnerability_id"))
                add_unique(item["artifact_ids"], artifact_id)
                for project_id in project_ids_for(artifact_projects, artifact_id):
                    add_unique(item["project_ids"], project_id)
                item["finding_count"] += 1
                if finding.get("fix_available"):
                    item["fixable_count"] += 1
                    item["remediation_available"] = True
                else:
                    item["not_fixable_count"] += 1
                for version in finding.get("fixed_versions", []) or []:
                    add_unique(item["fixed_versions"], version)
                severity = normalize_severity(finding.get("severity"))
                item["severity_counts"][severity] += 1
                item["highest_severity"] = highest_severity([item["highest_severity"], severity])
        final_data = []
        for package_id, item in index.items():
            item["artifact_ids"] = sorted(item["artifact_ids"])
            item["project_ids"] = sorted(item["project_ids"])
            item["vulnerability_ids"] = sorted(item["vulnerability_ids"])
            item["fixed_versions"] = sorted(item["fixed_versions"])
            item["security_status"] = security_status(item["fixable_count"], item["finding_count"])
            item["critical_high_count"] = item["severity_counts"].get("Critical", 0) + item["severity_counts"].get("High", 0)
            final_data.append(item)
            manifests["packages"][package_id] = {**id_fields(package_id, "package"), "partition": f"indexes/by-package/by-type/{package_file.stem}.json", "entity_partition": f"entities/packages/by-type/{package_file.name}", "package_type": item.get("package_type", ""), "package_name": item.get("package_name", ""), "package_version": item.get("package_version", "")}
        final_data.sort(key=lambda x: (-severity_rank(x.get("highest_severity")), not x.get("remediation_available"), -x.get("finding_count", 0), x.get("package_name", "")))
        write_package_index_partition(current_dir, package_file.stem, final_data)
        summary["package_count"] += len(final_data)
        written_partitions += 1
    return written_partitions


def build_by_vulnerability(current_dir, artifact_projects, manifests, summary):
    written_partitions = 0
    finding_files_list = finding_files(current_dir)
    for vuln_file in vulnerability_partition_files(current_dir):
        vulnerabilities = {item.get("vulnerability_id"): compact_vulnerability(item) for item in load_json_records(vuln_file) if item.get("vulnerability_id")}
        index = {vulnerability_id: {**vulnerability, "artifact_ids": [], "project_ids": [], "package_ids": [], "finding_count": 0, "fixable_count": 0, "not_fixable_count": 0, "security_status": "Not fixable", "remediation_available": False, "fixed_versions": [], "severity_counts": empty_severity_counts(), "highest_severity": vulnerability.get("severity", "Unknown"), "critical_high_count": 0} for vulnerability_id, vulnerability in vulnerabilities.items()}
        for findings_file in finding_files_list:
            artifact_id, findings = load_findings(findings_file)
            for finding in findings:
                vulnerability_id = finding.get("vulnerability_id")
                if vulnerability_id not in index:
                    continue
                item = index[vulnerability_id]
                add_unique(item["artifact_ids"], artifact_id)
                add_unique(item["package_ids"], finding.get("package_id"))
                for project_id in project_ids_for(artifact_projects, artifact_id):
                    add_unique(item["project_ids"], project_id)
                item["finding_count"] += 1
                if finding.get("fix_available"):
                    item["fixable_count"] += 1
                    item["remediation_available"] = True
                else:
                    item["not_fixable_count"] += 1
                for version in finding.get("fixed_versions", []) or []:
                    add_unique(item["fixed_versions"], version)
                severity = normalize_severity(finding.get("severity"))
                item["severity_counts"][severity] += 1
                item["highest_severity"] = highest_severity([item["highest_severity"], severity])
        final_data = []
        for vulnerability_id, item in index.items():
            item["artifact_ids"] = sorted(item["artifact_ids"])
            item["project_ids"] = sorted(item["project_ids"])
            item["package_ids"] = sorted(item["package_ids"])
            item["fixed_versions"] = sorted(item["fixed_versions"])
            item["security_status"] = security_status(item["fixable_count"], item["finding_count"])
            item["critical_high_count"] = item["severity_counts"].get("Critical", 0) + item["severity_counts"].get("High", 0)
            final_data.append(item)
            canonical_manifest = {**id_fields(vulnerability_id, "vulnerability"), "partition": f"indexes/by-vulnerability/by-year/{vuln_file.stem}.json", "entity_partition": f"entities/vulnerabilities/by-year/{vuln_file.name}", "severity": item.get("severity", "Unknown"), "highest_severity": item.get("highest_severity", "Unknown"), "aliases": item.get("aliases", []), "source_ids": item.get("source_ids", [])}
            manifests["vulnerabilities"][vulnerability_id] = canonical_manifest
            for alias in item.get("aliases", []) or []:
                if alias != vulnerability_id:
                    manifests["vulnerabilities"][alias] = {
                        **id_fields(alias, "vulnerability-alias"),
                        "alias_of": vulnerability_id,
                        "partition": canonical_manifest["partition"],
                        "entity_partition": canonical_manifest["entity_partition"],
                        "severity": item.get("severity", "Unknown"),
                        "highest_severity": item.get("highest_severity", "Unknown"),
                    }

        final_data.sort(key=lambda x: (-severity_rank(x.get("highest_severity")), not x.get("remediation_available"), -x.get("finding_count", 0), x.get("vulnerability_id", "")))
        write_vulnerability_index_partition(current_dir, vuln_file.stem, final_data)
        summary["vulnerability_count"] += len(final_data)
        written_partitions += 1
    return written_partitions


def build_remediation(current_dir, artifact_projects, manifests, summary):
    remediation = {}
    for findings_file in finding_files(current_dir):
        artifact_id, findings = load_findings(findings_file)
        for finding in findings:
            if not finding.get("fix_available"):
                continue
            fixed_versions = finding.get("fixed_versions") or []
            key = "|".join([finding.get("vulnerability_id", ""), finding.get("package_id", ""), ",".join(fixed_versions)])
            if key not in remediation:
                remediation[key] = {**id_fields(key, "remediation"), "remediation_id": key, "vulnerability_id": finding.get("vulnerability_id", ""), "package_id": finding.get("package_id", ""), "vulnerability_route_id": id_fields(finding.get("vulnerability_id", ""), "vulnerability")["route_id"], "package_route_id": id_fields(finding.get("package_id", ""), "package")["route_id"], "fixed_versions": fixed_versions, "highest_severity": finding.get("severity", "Unknown"), "finding_count": 0, "affected_artifact_ids": [], "affected_project_ids": [], "severity_counts": empty_severity_counts(), "search_text": " ".join([finding.get("vulnerability_id", ""), finding.get("package_id", ""), " ".join(fixed_versions)]).lower(), "labels": ["fixable"]}
            item = remediation[key]
            item["highest_severity"] = highest_severity([item.get("highest_severity"), finding.get("severity")])
            item["finding_count"] += 1
            item["severity_counts"][normalize_severity(finding.get("severity"))] += 1
            add_unique(item["affected_artifact_ids"], artifact_id)
            for project_id in project_ids_for(artifact_projects, artifact_id):
                add_unique(item["affected_project_ids"], project_id)
    result = []
    for item in remediation.values():
        item["affected_artifact_ids"] = sorted(item["affected_artifact_ids"])
        item["affected_project_ids"] = sorted(item["affected_project_ids"])
        item["affected_artifact_count"] = len(item["affected_artifact_ids"])
        item["affected_project_count"] = len(item["affected_project_ids"])
        result.append(item)
        manifests["remediation"][item["remediation_id"]] = {**id_fields(item["remediation_id"], "remediation"), "partition": "indexes/remediation.json", "vulnerability_id": item["vulnerability_id"], "package_id": item["package_id"], "highest_severity": item["highest_severity"], "affected_artifact_count": item["affected_artifact_count"]}
    result.sort(key=lambda x: (-severity_rank(x.get("highest_severity")), -x.get("affected_artifact_count", 0), x.get("vulnerability_id", ""), x.get("package_id", "")))
    write_remediation_index(current_dir, result)
    summary["remediation_count"] = len(result)
    return len(result)


def build_validation(current_dir, manifests, artifacts):
    warnings = []
    route_ids = {}
    for manifest_name, mapping in manifests.items():
        for canonical, item in mapping.items():
            route = item.get("route_id")
            if route in route_ids:
                warnings.append({"type": "duplicate_route_id", "route_id": route, "first": route_ids[route], "second": canonical, "manifest": manifest_name})
            route_ids[route] = canonical
    artifact_ids = set(artifacts.keys())
    package_ids = set(manifests["packages"].keys())
    vulnerability_ids = {key for key, item in manifests["vulnerabilities"].items() if not item.get("alias_of")}
    for findings_file in finding_files(current_dir):
        artifact_id, findings = load_findings(findings_file)
        if artifact_id not in artifact_ids:
            warnings.append({"type": "missing_artifact_reference", "artifact_id": artifact_id})
        for finding in findings:
            if finding.get("package_id") not in package_ids:
                warnings.append({"type": "missing_package_reference", "artifact_id": artifact_id, "package_id": finding.get("package_id"), "finding_id": finding.get("finding_id")})
            if finding.get("vulnerability_id") not in vulnerability_ids:
                warnings.append({"type": "missing_vulnerability_reference", "artifact_id": artifact_id, "vulnerability_id": finding.get("vulnerability_id"), "finding_id": finding.get("finding_id")})
    return {"schema_version": SCHEMA_VERSION, "index_version": INDEX_VERSION, "generated_at": utc_now(), "warning_count": len(warnings), "warnings": warnings}


def build_all_indexes(current_dir: Path):
    reset_indexes(current_dir)
    artifacts = load_artifacts(current_dir)
    artifact_projects = load_project_artifacts(current_dir)
    source_run = {}
    try:
        from orgdata.runtime.io import read_json
        source_run = read_json(current_dir / "run" / "run-metadata.json")
    except Exception:
        source_run = {}
    manifests = {"artifacts": {}, "packages": {}, "vulnerabilities": {}, "remediation": {}}
    summary = {"schema_version": SCHEMA_VERSION, "index_version": INDEX_VERSION, "generated_at": utc_now(), "source_run_id": (source_run or {}).get("run_id"), "source_finished_at": (source_run or {}).get("finished_at"), "artifact_count": 0, "package_count": 0, "vulnerability_count": 0, "finding_count": 0, "fixable_count": 0, "not_fixable_count": 0, "remediation_count": 0, "severity_totals": empty_severity_counts(), "partition_counts": {}}
    counts = {"by_artifact_count": build_by_artifact(current_dir, artifacts, artifact_projects, manifests, summary), "by_package_partition_count": build_by_package(current_dir, artifact_projects, manifests, summary), "by_vulnerability_partition_count": build_by_vulnerability(current_dir, artifact_projects, manifests, summary), "remediation_item_count": build_remediation(current_dir, artifact_projects, manifests, summary)}
    partitions = {"package_index_partitions": sorted({item.get("package_type", "unknown") for item in manifests["packages"].values()}), "vulnerability_index_partitions": sorted({item.get("partition", "").split("/")[-1].replace(".json", "") for item in manifests["vulnerabilities"].values()}), "artifact_index_count": len(manifests["artifacts"]), "remediation_index_count": len(manifests["remediation"])}
    summary["partition_counts"] = partitions
    write_manifest(current_dir, "artifacts", manifests["artifacts"])
    write_manifest(current_dir, "packages", manifests["packages"])
    write_manifest(current_dir, "vulnerabilities", manifests["vulnerabilities"])
    write_manifest(current_dir, "remediation", manifests["remediation"])
    write_manifest(current_dir, "partitions", partitions)
    validation = build_validation(current_dir, manifests, artifacts)
    write_index_validation(current_dir, validation)
    write_index_summary(current_dir, summary)
    metadata = {"schema_version": SCHEMA_VERSION, "index_version": INDEX_VERSION, "generated_at": utc_now(), "source_run_id": summary.get("source_run_id"), "source_finished_at": summary.get("source_finished_at"), "generator": "org-data-generator", "counts": counts, "summary_path": "indexes/index-summary.json", "validation_path": "indexes/index-validation.json", "manifests": {"artifacts": "indexes/manifests/artifacts.json", "packages": "indexes/manifests/packages.json", "vulnerabilities": "indexes/manifests/vulnerabilities.json", "remediation": "indexes/manifests/remediation.json", "partitions": "indexes/manifests/partitions.json"}}
    write_index_metadata(current_dir, metadata)
    return metadata