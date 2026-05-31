import argparse
import uuid
from datetime import datetime, timezone
from pathlib import Path

from orgdata.inventory.builder import build_inventory_records
from orgdata.runtime.discovery import discover_result_folders
from orgdata.runtime.io import read_json, reset_dir, write_json
from orgdata.validation.references import validate_references
from orgdata.vulnerabilities.builder import build_vulnerability_records, compare_findings
from orgdata.vulnerabilities.grype import get_grype_version, scan_sbom, update_grype_db


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def error_entry(artifact_folder, stage, error_type, message, **extra):
    return {"artifact_folder": artifact_folder, "stage": stage, "error_type": error_type, "message": message, **extra}

SEVERITY_RANK = {
    "Unknown": 0,
    "Negligible": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}

def merge_unique(existing, values):
    merged = list(existing or [])
    if values is None:
        return merged
    if not isinstance(values, list):
        values = [values]
    for value in values:
        if value not in (None, "") and value not in merged:
            merged.append(value)
    return merged


def first_non_empty(existing, new):
    return existing if existing not in (None, "", []) else new


def severity_rank(value):
    return SEVERITY_RANK.get(value or "Unknown", 0)


def merge_cvss(existing, values):
    merged = list(existing or [])
    seen = {
        "|".join([
            str(item.get("source", "")),
            str(item.get("type", "")),
            str(item.get("version", "")),
            str(item.get("vector", "")),
        ])
        for item in merged
        if isinstance(item, dict)
    }

    for item in values or []:
        if not isinstance(item, dict):
            continue
        key = "|".join([
            str(item.get("source", "")),
            str(item.get("type", "")),
            str(item.get("version", "")),
            str(item.get("vector", "")),
        ])
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


def merge_package_entity(existing, new):
    for field in (
        "package_name",
        "package_version",
        "package_type",
        "package_group",
        "component_type",
        "normalized_purl",
        "publisher",
    ):
        existing[field] = first_non_empty(existing.get(field), new.get(field))

    existing["purls"] = merge_unique(existing.get("purls"), new.get("purls"))
    existing["licenses"] = merge_unique(existing.get("licenses"), new.get("licenses"))

    return existing


def merge_vulnerability_entity(existing, new):
    existing["severity"] = (
        new.get("severity")
        if severity_rank(new.get("severity")) > severity_rank(existing.get("severity"))
        else existing.get("severity")
    )

    existing["namespaces"] = merge_unique(existing.get("namespaces"), new.get("namespaces"))
    existing["data_sources"] = merge_unique(existing.get("data_sources"), new.get("data_sources"))
    existing["urls"] = merge_unique(existing.get("urls"), new.get("urls"))
    existing["cwes"] = merge_unique(existing.get("cwes"), new.get("cwes"))
    existing["cvss"] = merge_cvss(existing.get("cvss"), new.get("cvss"))

    existing["description"] = first_non_empty(existing.get("description"), new.get("description"))
    existing["epss"] = latest_epss(existing.get("epss"), new.get("epss"))

    if existing.get("risk_score") is None:
        existing["risk_score"] = new.get("risk_score")
    elif new.get("risk_score") is not None:
        existing["risk_score"] = max(existing.get("risk_score"), new.get("risk_score"))

    return existing


def merge_entity_by_id(existing, records, id_field, merge_func):
    for record in records:
        key = record.get(id_field)
        if not key:
            continue
        if key in existing:
            existing[key] = merge_func(existing[key], record)
        else:
            existing[key] = record
    return existing

def log(message):
    print(f"[org-data] {message}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Generate normalized current-state org security data from scan result folders.")
    parser.add_argument("results_dir", help="Path to results directory, e.g. /results")
    parser.add_argument("--org-data-dir", default="/org-data", help="Path to org-data output directory")
    parser.add_argument("--skip-vuln-refresh", action="store_true", help="Do not rerun Grype; parse existing grype-sbom-vulns.json files only")
    args = parser.parse_args()

    started_at = utc_now()
    run_id = str(uuid.uuid4())
    results_dir = Path(args.results_dir).resolve()
    org_data_dir = Path(args.org_data_dir).resolve()
    current_dir = org_data_dir / "current"

    if not results_dir.is_dir():
        raise SystemExit(f"Results directory does not exist or is not a directory: {results_dir}")

    log(f"Starting org data generation")
    log(f"Results dir: {results_dir}")
    log(f"Org data dir: {org_data_dir}")
    log(f"Vulnerability refresh enabled: {not args.skip_vuln_refresh}")

    reset_dir(current_dir)

    folders, discovery_errors = discover_result_folders(results_dir)
    run_errors = list(discovery_errors)
    reference_warnings = []
    log(f"Discovered folders: valid={len(folders)}, skipped={len(discovery_errors)}")

    projects = {}
    artifacts = {}
    packages = {}
    vulnerabilities = {}
    project_artifacts = {}
    artifact_packages = {}
    findings = {}
    finding_changes = {"new": [], "changed": []}

    grype_version = get_grype_version()
    grype_db = None
    if not args.skip_vuln_refresh:
        log("Updating/checking Grype vulnerability database")
        grype_db = update_grype_db()
        log("Grype database update/check completed")
        if grype_db.get("update", {}).get("returncode") not in (0, None):
            run_errors.append(error_entry("__global__", "grype_db_update", "grype_db_update_failed", grype_db.get("update", {}).get("stderr", "Grype DB update failed")))

    processed_count = 0
    failed_count = 0

    for folder in folders:
        folder_name = folder.name
        log(f"Processing artifact folder: {folder_name}")        
        metadata_path = folder / "metadata.json"
        sbom_path = folder / "sbom-cyclonedx.json"
        vuln_path = folder / "grype-sbom-vulns.json"
        table_path = folder / "grype-sbom-vulns.table.txt"

        try:
            metadata = read_json(metadata_path)
            sbom_data = read_json(sbom_path)
        except Exception as exc:
            failed_count += 1
            run_errors.append(error_entry(folder_name, "input_parse", "invalid_input_json", str(exc)))
            continue

        try:
            inv = build_inventory_records(folder_name, metadata, sbom_data)
            artifact = inv["artifact"]
            artifact_id = artifact["artifact_id"]
            artifacts[artifact_id] = artifact
            if inv.get("project"):
                projects[inv["project"]["project_id"]] = inv["project"]
            if inv.get("project_artifact"):
                project_artifacts["|".join([inv["project_artifact"]["project_id"], artifact_id])] = inv["project_artifact"]
            merge_entity_by_id(packages, inv.get("packages", []), "package_id", merge_package_entity)
            for rel in inv.get("artifact_packages", []):
                artifact_packages["|".join([rel["artifact_id"], rel["package_id"]])] = rel
            reference_warnings.extend(inv.get("warnings", []))
            log(
                f"Inventory built for {artifact_id}: "
                f"packages={len(inv.get('packages', []))}, "
                f"artifact_package_links={len(inv.get('artifact_packages', []))}"
            )
        except Exception as exc:
            failed_count += 1
            run_errors.append(error_entry(folder_name, "inventory_build", "inventory_build_failed", str(exc)))
            continue

        old_findings = []
        if vuln_path.is_file():
            try:
                _, old_findings = build_vulnerability_records(artifact_id, read_json(vuln_path))
            except Exception as exc:
                run_errors.append(error_entry(folder_name, "old_vulnerability_parse", "invalid_old_grype_json", str(exc)))

        if not args.skip_vuln_refresh:
            log(f"Refreshing SBOM vulnerability scan for {artifact_id}")
            scan_result = scan_sbom(sbom_path, vuln_path, table_path)
            if not scan_result.get("ok"):
                run_errors.append(error_entry(folder_name, scan_result.get("stage", "grype_scan"), "grype_scan_failed", scan_result.get("stderr", "Grype scan failed"), returncode=scan_result.get("returncode")))
                processed_count += 1
                continue
            log(f"Vulnerability scan refreshed for {artifact_id}")

        if vuln_path.is_file():
            try:
                vuln_records, new_findings = build_vulnerability_records(artifact_id, read_json(vuln_path))
                merge_entity_by_id(
                    vulnerabilities,
                    vuln_records,
                    "vulnerability_id",
                    merge_vulnerability_entity,
                )
                for finding in new_findings:
                    findings[finding["finding_id"]] = finding
                changes = compare_findings(old_findings, new_findings) if old_findings else {"new": new_findings, "changed": []}
                finding_changes["new"].extend(changes["new"])
                finding_changes["changed"].extend(changes["changed"])
            except Exception as exc:
                run_errors.append(error_entry(folder_name, "vulnerability_parse", "invalid_grype_json", str(exc)))
        else:
            run_errors.append(error_entry(folder_name, "vulnerability_parse", "missing_grype_sbom_vulns", "grype-sbom-vulns.json is missing"))

        processed_count += 1
        log(
            f"Vulnerabilities parsed for {artifact_id}: "
            f"vulnerabilities={len(vuln_records)}, findings={len(new_findings)}"
        )

    project_list = sorted(projects.values(), key=lambda x: x.get("project_id", ""))
    artifact_list = sorted(artifacts.values(), key=lambda x: x.get("artifact_id", ""))
    package_list = sorted(packages.values(), key=lambda x: x.get("package_id", ""))
    vulnerability_list = sorted(vulnerabilities.values(), key=lambda x: x.get("vulnerability_id", ""))
    project_artifact_list = sorted(project_artifacts.values(), key=lambda x: (x.get("project_id", ""), x.get("artifact_id", "")))
    artifact_package_list = sorted(artifact_packages.values(), key=lambda x: (x.get("artifact_id", ""), x.get("package_id", "")))
    finding_list = sorted(findings.values(), key=lambda x: x.get("finding_id", ""))

    log("Validating references")
    reference_warnings.extend(validate_references(artifact_list, package_list, vulnerability_list, artifact_package_list, finding_list))

    run_metadata = {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": utc_now(),
        "results_dir": str(results_dir),
        "org_data_dir": str(org_data_dir),
        "vulnerability_refresh_enabled": not args.skip_vuln_refresh,
        "grype_version": grype_version,
        "grype_db": grype_db,
        "total_folders_discovered": len(folders) + len(discovery_errors),
        "valid_folders": len(folders),
        "processed_count": processed_count,
        "skipped_count": len(discovery_errors),
        "failed_count": failed_count,
        "project_count": len(project_list),
        "artifact_count": len(artifact_list),
        "package_count": len(package_list),
        "vulnerability_count": len(vulnerability_list),
        "artifact_package_relationship_count": len(artifact_package_list),
        "finding_count": len(finding_list),
        "new_finding_count": len(finding_changes["new"]),
        "changed_finding_count": len(finding_changes["changed"]),
        "error_count": len(run_errors),
        "reference_warning_count": len(reference_warnings),
    }

    log("Writing normalized org data files")
    write_json(current_dir / "entities" / "projects.json", project_list)
    write_json(current_dir / "entities" / "artifacts.json", artifact_list)
    write_json(current_dir / "entities" / "packages.json", package_list)
    write_json(current_dir / "entities" / "vulnerabilities.json", vulnerability_list)
    write_json(current_dir / "relationships" / "project-artifacts.json", project_artifact_list)
    write_json(current_dir / "relationships" / "artifact-packages.json", artifact_package_list)
    write_json(current_dir / "relationships" / "findings.json", finding_list)
    write_json(current_dir / "relationships" / "finding-changes.json", finding_changes)
    write_json(current_dir / "run" / "run-metadata.json", run_metadata)
    write_json(current_dir / "run" / "run-errors.json", run_errors)
    write_json(current_dir / "run" / "reference-warnings.json", reference_warnings)
    log("Finished writing normalized org data files")

    print(
        f"Org data generation completed: processed={processed_count}, artifacts={len(artifact_list)}, "
        f"projects={len(project_list)}, packages={len(package_list)}, vulnerabilities={len(vulnerability_list)}, "
        f"findings={len(finding_list)}, errors={len(run_errors)}, warnings={len(reference_warnings)}"
    )


if __name__ == "__main__":
    main()
