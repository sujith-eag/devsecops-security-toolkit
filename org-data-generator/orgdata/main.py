"""
Main orchestration entrypoint for org-data generation.

This module discovers scan result folders, parses metadata and SBOM files,
optionally refreshes Grype SBOM vulnerability output, writes partitioned
normalized entity and relationship data, builds query indexes, and writes run
metadata/errors.

It should remain orchestration-focused. Parsing, normalization, partitioning,
validation, and index creation should live in their dedicated modules.
"""

import argparse
import uuid
from datetime import datetime, timezone
from pathlib import Path

from orgdata.inventory.builder import build_inventory_records
from orgdata.inventory.sbom import merge_package
from orgdata.runtime.discovery import discover_result_folders
from orgdata.runtime.io import read_json, reset_dir, write_json
from orgdata.runtime.partitions import append_many_jsonl, finalize_partition_dir, safe_filename
from orgdata.validation.references import validate_artifact_references
from orgdata.vulnerabilities.builder import (
    build_vulnerability_records,
    compare_findings,
    group_findings_by_fixability_and_severity,
    merge_vulnerability,
    vulnerability_bucket,
)
from orgdata.vulnerabilities.grype import get_grype_version, scan_sbom, update_grype_db
from orgdata.indexes.builder import build_all_indexes


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(message):
    print(f"[org-data] {message}", flush=True)


def error_entry(artifact_folder, stage, error_type, message, **extra):
    return {"artifact_folder": artifact_folder, "stage": stage, "error_type": error_type, "message": message, **extra}


def main():
    parser = argparse.ArgumentParser(description="Generate partitioned normalized current-state org security data from scan result folders.")
    parser.add_argument("results_dir", help="Path to results directory, e.g. /results")
    parser.add_argument("--org-data-dir", default="/org-data", help="Path to org-data output directory")
    parser.add_argument("--skip-vuln-refresh", action="store_true", help="Do not rerun Grype; parse existing grype-sbom-vulns.json files only")
    args = parser.parse_args()

    started_at = utc_now()
    run_id = str(uuid.uuid4())
    results_dir = Path(args.results_dir).resolve()
    org_data_dir = Path(args.org_data_dir).resolve()
    current_dir = org_data_dir / "current"
    tmp_dir = current_dir / ".tmp"

    if not results_dir.is_dir():
        raise SystemExit(f"Results directory does not exist or is not a directory: {results_dir}")

    log("Starting org data generation")
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
    project_artifacts = {}
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
        metadata_path = folder / "metadata.json"
        sbom_path = folder / "sbom-cyclonedx.json"
        vuln_path = folder / "grype-sbom-vulns.json"
        table_path = folder / "grype-sbom-vulns.table.txt"
        log(f"Processing artifact folder: {folder_name}")

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

            for package in inv.get("packages", []):
                package_type = safe_filename(package.get("package_type", "unknown"))
                append_many_jsonl(tmp_dir / "packages" / "by-type" / f"{package_type}.jsonl", [package])

            artifact_package_file = current_dir / "relationships" / "artifact-packages" / "by-artifact" / f"{safe_filename(artifact_id)}.json"
            write_json(artifact_package_file, {
                "artifact_id": artifact_id,
                "package_count": len(inv.get("artifact_packages", [])),
                "packages": inv.get("artifact_packages", []),
            })
            reference_warnings.extend(inv.get("warnings", []))
            artifact_package_ids = {item.get("package_id") for item in inv.get("artifact_packages", [])}
            log(f"Inventory built for {artifact_id}: packages={len(inv.get('artifact_packages', []))}")
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
                for vulnerability in vuln_records:
                    bucket = safe_filename(vulnerability_bucket(vulnerability.get("vulnerability_id")))
                    append_many_jsonl(tmp_dir / "vulnerabilities" / "by-year" / f"{bucket}.jsonl", [vulnerability])

                findings_file = current_dir / "relationships" / "findings" / "by-artifact" / f"{safe_filename(artifact_id)}.json"
                write_json(findings_file, group_findings_by_fixability_and_severity(artifact_id, new_findings))

                if args.skip_vuln_refresh:
                    changes = {"new": [], "changed": []}
                else:
                    changes = compare_findings(old_findings, new_findings) if old_findings else {"new": new_findings, "changed": []}
                finding_changes["new"].extend(changes["new"])
                finding_changes["changed"].extend(changes["changed"])
                reference_warnings.extend(validate_artifact_references(artifact_id, artifact_package_ids, new_findings))
                log(f"Vulnerabilities parsed for {artifact_id}: vulnerabilities={len(vuln_records)}, findings={len(new_findings)}")
            except Exception as exc:
                run_errors.append(error_entry(folder_name, "vulnerability_parse", "invalid_grype_json", str(exc)))
        else:
            run_errors.append(error_entry(folder_name, "vulnerability_parse", "missing_grype_sbom_vulns", "grype-sbom-vulns.json is missing"))

        processed_count += 1

    log("Finalizing package partitions")
    package_files, package_ids = finalize_partition_dir(tmp_dir / "packages" / "by-type", current_dir / "entities" / "packages" / "by-type", "package_id", merge_package)
    log("Finalizing vulnerability partitions")
    vulnerability_files, vulnerability_ids = finalize_partition_dir(tmp_dir / "vulnerabilities" / "by-year", current_dir / "entities" / "vulnerabilities" / "by-year", "vulnerability_id", merge_vulnerability)

    project_list = sorted(projects.values(), key=lambda x: x.get("project_id", ""))
    artifact_list = sorted(artifacts.values(), key=lambda x: x.get("artifact_id", ""))
    project_artifact_list = sorted(project_artifacts.values(), key=lambda x: (x.get("project_id", ""), x.get("artifact_id", "")))

    log("Writing core entity and run files")
    write_json(current_dir / "entities" / "projects.json", project_list)
    write_json(current_dir / "entities" / "artifacts.json", artifact_list)
    write_json(current_dir / "relationships" / "project-artifacts.json", project_artifact_list)
    write_json(current_dir / "relationships" / "finding-changes.json", finding_changes)
    write_json(current_dir / "run" / "run-errors.json", run_errors)
    write_json(current_dir / "run" / "reference-warnings.json", reference_warnings)

    # Creatng the Indexes from 
    log("Building query indexes")
    index_metadata = build_all_indexes(current_dir)
    log("Finished building query indexes")

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
        "package_count": len(package_ids),
        "vulnerability_count": len(vulnerability_ids),
        "package_partition_files": package_files,
        "vulnerability_partition_files": vulnerability_files,
        "project_artifact_relationship_count": len(project_artifact_list),
        "new_finding_count": len(finding_changes["new"]),
        "changed_finding_count": len(finding_changes["changed"]),
        "error_count": len(run_errors),
        "reference_warning_count": len(reference_warnings),
        "index_metadata": index_metadata,
    }
    write_json(current_dir / "run" / "run-metadata.json", run_metadata)
    log("Finished writing normalized org data files")

    print(
        f"Org data generation completed: processed={processed_count}, artifacts={len(artifact_list)}, "
        f"projects={len(project_list)}, packages={len(package_ids)}, vulnerabilities={len(vulnerability_ids)}, "
        f"errors={len(run_errors)}, warnings={len(reference_warnings)}",
        flush=True,
    )


if __name__ == "__main__":
    main()
