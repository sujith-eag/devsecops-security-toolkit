"""
Builds query-friendly indexes from normalized org-data.

Indexes are derived and disposable. They provide the main abstraction layer for
reports, dashboards, Web UI, and external queries so those consumers do not need
to understand the full partitioned entity/relationship layout.
"""

from pathlib import Path

from orgdata.indexes.loader import (
    artifact_package_files,
    finding_files,
    load_artifact_packages,
    load_artifact_projects,
    load_artifacts,
    load_findings,
    load_json_list,
    package_partition_files,
    vulnerability_partition_files,
)
from orgdata.indexes.writer import (
    reset_indexes,
    write_artifact_index,
    write_package_index_partition,
    write_remediation_index,
    write_vulnerability_index_partition,
)
from orgdata.normalize.severity import SEVERITIES, empty_severity_counts, highest_severity, normalize_severity


def _add_unique(target, value):
    if value not in (None, "") and value not in target:
        target.append(value)


def _sorted_unique(values):
    return sorted(v for v in set(values or []) if v not in (None, ""))


def _project_ids(artifact_projects, artifact_id):
    return sorted(artifact_projects.get(artifact_id, set()))


def _compact_artifact(artifact):
    return {
        "artifact_id": artifact.get("artifact_id", ""),
        "artifact_folder": artifact.get("artifact_folder", ""),
        "artifact_type": artifact.get("artifact_type", ""),
        "artifact_role": artifact.get("artifact_role", ""),
        "project_id": artifact.get("project_id", ""),
        "image": artifact.get("image", {}),
        "source": artifact.get("source", {}),
    }


def _compact_package(package):
    return {
        "package_id": package.get("package_id", ""),
        "package_name": package.get("package_name", ""),
        "package_version": package.get("package_version", ""),
        "package_type": package.get("package_type", ""),
        "package_group": package.get("package_group", ""),
        "normalized_purl": package.get("normalized_purl", ""),
    }


def _compact_vulnerability(vulnerability):
    return {
        "vulnerability_id": vulnerability.get("vulnerability_id", ""),
        "severity": vulnerability.get("severity", "Unknown"),
        "namespaces": vulnerability.get("namespaces", []),
        "data_sources": vulnerability.get("data_sources", []),
        "cwes": vulnerability.get("cwes", []),
        "epss": vulnerability.get("epss"),
        "risk_score": vulnerability.get("risk_score"),
    }


def _collect_findings_by_artifact(current_dir):
    result = {}
    for path in finding_files(current_dir):
        artifact_id, findings = load_findings(path)
        if artifact_id:
            result[artifact_id] = findings
    return result


def _collect_artifact_packages_by_artifact(current_dir):
    result = {}
    for path in artifact_package_files(current_dir):
        artifact_id, packages = load_artifact_packages(path)
        if artifact_id:
            result[artifact_id] = packages
    return result


def build_by_artifact(current_dir: Path, artifacts, artifact_projects):
    artifact_packages = _collect_artifact_packages_by_artifact(current_dir)
    findings_by_artifact = _collect_findings_by_artifact(current_dir)
    written = 0

    for artifact_id, artifact in artifacts.items():
        package_links = artifact_packages.get(artifact_id, [])
        findings = findings_by_artifact.get(artifact_id, [])
        package_ids = _sorted_unique([item.get("package_id") for item in package_links])
        vulnerable_package_ids = _sorted_unique([item.get("package_id") for item in findings])
        vulnerability_ids = _sorted_unique([item.get("vulnerability_id") for item in findings])
        severity_counts = empty_severity_counts()
        fixable_count = 0

        for finding in findings:
            severity_counts[normalize_severity(finding.get("severity"))] += 1
            if finding.get("fix_available"):
                fixable_count += 1

        write_artifact_index(current_dir, artifact_id, {
            "artifact": _compact_artifact(artifact),
            "project_ids": _project_ids(artifact_projects, artifact_id),
            "package_count": len(package_ids),
            "vulnerable_package_count": len(vulnerable_package_ids),
            "finding_count": len(findings),
            "vulnerability_count": len(vulnerability_ids),
            "fixable_count": fixable_count,
            "not_fixable_count": len(findings) - fixable_count,
            "severity_counts": severity_counts,
            "package_ids": package_ids,
            "vulnerable_package_ids": vulnerable_package_ids,
            "vulnerability_ids": vulnerability_ids,
        })
        written += 1

    return written


def build_by_package(current_dir: Path, artifact_projects):
    written_partitions = 0
    artifact_package_files_list = artifact_package_files(current_dir)
    finding_files_list = finding_files(current_dir)

    for package_file in package_partition_files(current_dir):
        packages = {_item.get("package_id"): _compact_package(_item) for _item in load_json_list(package_file) if _item.get("package_id")}
        index = {
            package_id: {
                **package,
                "artifact_ids": [],
                "project_ids": [],
                "vulnerability_ids": [],
                "finding_count": 0,
                "fixable_count": 0,
                "not_fixable_count": 0,
                "severity_counts": empty_severity_counts(),
            }
            for package_id, package in packages.items()
        }

        for rel_file in artifact_package_files_list:
            artifact_id, package_links = load_artifact_packages(rel_file)
            for link in package_links:
                package_id = link.get("package_id")
                if package_id in index:
                    _add_unique(index[package_id]["artifact_ids"], artifact_id)
                    for project_id in _project_ids(artifact_projects, artifact_id):
                        _add_unique(index[package_id]["project_ids"], project_id)

        for findings_file in finding_files_list:
            artifact_id, findings = load_findings(findings_file)
            for finding in findings:
                package_id = finding.get("package_id")
                if package_id not in index:
                    continue
                _add_unique(index[package_id]["vulnerability_ids"], finding.get("vulnerability_id"))
                _add_unique(index[package_id]["artifact_ids"], artifact_id)
                for project_id in _project_ids(artifact_projects, artifact_id):
                    _add_unique(index[package_id]["project_ids"], project_id)
                index[package_id]["finding_count"] += 1
                if finding.get("fix_available"):
                    index[package_id]["fixable_count"] += 1
                else:
                    index[package_id]["not_fixable_count"] += 1
                index[package_id]["severity_counts"][normalize_severity(finding.get("severity"))] += 1

        final_data = []
        for item in index.values():
            item["artifact_ids"] = sorted(item["artifact_ids"])
            item["project_ids"] = sorted(item["project_ids"])
            item["vulnerability_ids"] = sorted(item["vulnerability_ids"])
            final_data.append(item)

        final_data.sort(key=lambda x: (-x.get("finding_count", 0), x.get("package_name", ""), x.get("package_version", "")))
        write_package_index_partition(current_dir, package_file.stem, final_data)
        written_partitions += 1

    return written_partitions


def build_by_vulnerability(current_dir: Path, artifact_projects):
    written_partitions = 0
    finding_files_list = finding_files(current_dir)

    for vuln_file in vulnerability_partition_files(current_dir):
        vulnerabilities = {item.get("vulnerability_id"): _compact_vulnerability(item) for item in load_json_list(vuln_file) if item.get("vulnerability_id")}
        index = {
            vulnerability_id: {
                **vulnerability,
                "artifact_ids": [],
                "project_ids": [],
                "package_ids": [],
                "finding_count": 0,
                "fixable_count": 0,
                "not_fixable_count": 0,
                "severity_counts": empty_severity_counts(),
            }
            for vulnerability_id, vulnerability in vulnerabilities.items()
        }

        for findings_file in finding_files_list:
            artifact_id, findings = load_findings(findings_file)
            for finding in findings:
                vulnerability_id = finding.get("vulnerability_id")
                if vulnerability_id not in index:
                    continue
                _add_unique(index[vulnerability_id]["artifact_ids"], artifact_id)
                _add_unique(index[vulnerability_id]["package_ids"], finding.get("package_id"))
                for project_id in _project_ids(artifact_projects, artifact_id):
                    _add_unique(index[vulnerability_id]["project_ids"], project_id)
                index[vulnerability_id]["finding_count"] += 1
                if finding.get("fix_available"):
                    index[vulnerability_id]["fixable_count"] += 1
                else:
                    index[vulnerability_id]["not_fixable_count"] += 1
                index[vulnerability_id]["severity_counts"][normalize_severity(finding.get("severity"))] += 1

        final_data = []
        for item in index.values():
            item["artifact_ids"] = sorted(item["artifact_ids"])
            item["project_ids"] = sorted(item["project_ids"])
            item["package_ids"] = sorted(item["package_ids"])
            final_data.append(item)

        final_data.sort(key=lambda x: (-x.get("finding_count", 0), x.get("vulnerability_id", "")))
        write_vulnerability_index_partition(current_dir, vuln_file.stem, final_data)
        written_partitions += 1

    return written_partitions


def build_remediation(current_dir: Path, artifact_projects):
    remediation = {}

    for findings_file in finding_files(current_dir):
        artifact_id, findings = load_findings(findings_file)
        for finding in findings:
            if not finding.get("fix_available"):
                continue
            fixed_versions = finding.get("fixed_versions") or []
            key = "|".join([
                finding.get("vulnerability_id", ""),
                finding.get("package_id", ""),
                ",".join(fixed_versions),
            ])
            if key not in remediation:
                remediation[key] = {
                    "remediation_id": key,
                    "vulnerability_id": finding.get("vulnerability_id", ""),
                    "package_id": finding.get("package_id", ""),
                    "fixed_versions": fixed_versions,
                    "highest_severity": finding.get("severity", "Unknown"),
                    "finding_count": 0,
                    "affected_artifact_ids": [],
                    "affected_project_ids": [],
                    "severity_counts": empty_severity_counts(),
                }

            item = remediation[key]
            item["highest_severity"] = highest_severity([item.get("highest_severity"), finding.get("severity")])
            item["finding_count"] += 1
            item["severity_counts"][normalize_severity(finding.get("severity"))] += 1
            _add_unique(item["affected_artifact_ids"], artifact_id)
            for project_id in _project_ids(artifact_projects, artifact_id):
                _add_unique(item["affected_project_ids"], project_id)

    result = []
    for item in remediation.values():
        item["affected_artifact_ids"] = sorted(item["affected_artifact_ids"])
        item["affected_project_ids"] = sorted(item["affected_project_ids"])
        item["affected_artifact_count"] = len(item["affected_artifact_ids"])
        item["affected_project_count"] = len(item["affected_project_ids"])
        result.append(item)

    result.sort(key=lambda x: (-x.get("finding_count", 0), x.get("vulnerability_id", ""), x.get("package_id", "")))
    write_remediation_index(current_dir, result)
    return len(result)


def build_all_indexes(current_dir: Path):
    reset_indexes(current_dir)
    artifacts = load_artifacts(current_dir)
    artifact_projects = load_artifact_projects(current_dir)

    return {
        "by_artifact_count": build_by_artifact(current_dir, artifacts, artifact_projects),
        "by_package_partition_count": build_by_package(current_dir, artifact_projects),
        "by_vulnerability_partition_count": build_by_vulnerability(current_dir, artifact_projects),
        "remediation_item_count": build_remediation(current_dir, artifact_projects),
    }
