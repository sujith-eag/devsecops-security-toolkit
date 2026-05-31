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


def merge_by_id(existing, records, id_field):
    for record in records:
        key = record.get(id_field)
        if key and key not in existing:
            existing[key] = record
    return existing


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

    reset_dir(current_dir)

    folders, discovery_errors = discover_result_folders(results_dir)
    run_errors = list(discovery_errors)
    reference_warnings = []

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
        grype_db = update_grype_db()
        if grype_db.get("update", {}).get("returncode") not in (0, None):
            run_errors.append(error_entry("__global__", "grype_db_update", "grype_db_update_failed", grype_db.get("update", {}).get("stderr", "Grype DB update failed")))

    processed_count = 0
    failed_count = 0

    for folder in folders:
        folder_name = folder.name
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
            merge_by_id(packages, inv.get("packages", []), "package_id")
            for rel in inv.get("artifact_packages", []):
                artifact_packages["|".join([rel["artifact_id"], rel["package_id"]])] = rel
            reference_warnings.extend(inv.get("warnings", []))
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
            scan_result = scan_sbom(sbom_path, vuln_path, table_path)
            if not scan_result.get("ok"):
                run_errors.append(error_entry(folder_name, scan_result.get("stage", "grype_scan"), "grype_scan_failed", scan_result.get("stderr", "Grype scan failed"), returncode=scan_result.get("returncode")))
                processed_count += 1
                continue

        if vuln_path.is_file():
            try:
                vuln_records, new_findings = build_vulnerability_records(artifact_id, read_json(vuln_path))
                merge_by_id(vulnerabilities, vuln_records, "vulnerability_id")
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

    project_list = sorted(projects.values(), key=lambda x: x.get("project_id", ""))
    artifact_list = sorted(artifacts.values(), key=lambda x: x.get("artifact_id", ""))
    package_list = sorted(packages.values(), key=lambda x: x.get("package_id", ""))
    vulnerability_list = sorted(vulnerabilities.values(), key=lambda x: x.get("vulnerability_id", ""))
    project_artifact_list = sorted(project_artifacts.values(), key=lambda x: (x.get("project_id", ""), x.get("artifact_id", "")))
    artifact_package_list = sorted(artifact_packages.values(), key=lambda x: (x.get("artifact_id", ""), x.get("package_id", "")))
    finding_list = sorted(findings.values(), key=lambda x: x.get("finding_id", ""))

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

    print(
        f"Org data generation completed: processed={processed_count}, artifacts={len(artifact_list)}, "
        f"projects={len(project_list)}, packages={len(package_list)}, vulnerabilities={len(vulnerability_list)}, "
        f"findings={len(finding_list)}, errors={len(run_errors)}, warnings={len(reference_warnings)}"
    )


if __name__ == "__main__":
    main()
