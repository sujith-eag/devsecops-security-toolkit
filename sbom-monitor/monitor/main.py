import argparse
import uuid
from datetime import datetime, timezone
from pathlib import Path

from monitor.runtime.archiver import archive_current
from monitor.runtime.discovery import discover_result_folders
from monitor.runtime.io import write_json, write_text

from monitor.scanner.grype import get_grype_version, scan_sbom, update_grype_db

from monitor.findings.normalizer import load_json, normalize_grype_data, deduplicate_findings
from monitor.findings.comparator import compare_findings

from monitor.indexes.builder import build_cve_index, build_image_index, build_package_index

from monitor.reports.overview import build_monitoring_overview
from monitor.reports.markdown import build_monitoring_report


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def error_entry(image_folder, stage, error_type, message, **extra):
    return {
        "image_folder": image_folder,
        "stage": stage,
        "error_type": error_type,
        "message": message,
        **extra,
    }


def main():
    parser = argparse.ArgumentParser(description="Refresh SBOM vulnerability scans and write global monitoring core data files.")
    parser.add_argument("results_dir", help="Path to runtime results directory, e.g. /results")
    parser.add_argument(
        "--monitoring-dir",
        default=None,
        help="Path to global monitoring output directory, e.g. /monitoring",
    )
    args = parser.parse_args()

    started_at = utc_now()
    run_id = str(uuid.uuid4())
    results_dir = Path(args.results_dir).resolve()
    monitoring_dir = Path(args.monitoring_dir).resolve() if args.monitoring_dir else results_dir / "monitoring"
    current_dir = monitoring_dir / "current"
    scan_errors = []
    all_findings = []
    finding_changes = {"new": [], "changed": []}

    if not results_dir.is_dir():
        raise SystemExit(f"Results directory does not exist or is not a directory: {results_dir}")

    archived_to = archive_current(monitoring_dir)
    current_dir.mkdir(parents=True, exist_ok=True)

    folders, skipped = discover_result_folders(results_dir)
    scan_errors.extend(skipped)

    grype_version = get_grype_version()
    grype_db = update_grype_db()
    if grype_db.get("update", {}).get("returncode") not in (0, None):
        scan_errors.append(error_entry(
            "__global__",
            "grype_db_update",
            "grype_db_update_failed",
            grype_db.get("update", {}).get("stderr", "Grype DB update failed"),
            stdout=grype_db.get("update", {}).get("stdout", ""),
            returncode=grype_db.get("update", {}).get("returncode"),
        ))

    scanned_count = 0
    failed_count = 0

    for folder in folders:
        image_folder = folder.name
        metadata_path = folder / "metadata.json"
        sbom_path = folder / "sbom-cyclonedx.json"
        vuln_path = folder / "grype-sbom-vulns.json"
        table_path = folder / "grype-sbom-vulns.table.txt"

        try:
            metadata = load_json(metadata_path)
        except Exception as exc:
            failed_count += 1
            scan_errors.append(error_entry(image_folder, "json_parse", "invalid_metadata_json", str(exc)))
            continue

        old_findings = []
        if vuln_path.is_file():
            try:
                old_findings = deduplicate_findings(
                    normalize_grype_data(load_json(vuln_path), metadata, image_folder)
                )

            except Exception as exc:
                scan_errors.append(error_entry(image_folder, "json_parse", "invalid_old_grype_json", str(exc)))

        scan_result = scan_sbom(sbom_path, vuln_path, table_path)
        if not scan_result.get("ok"):
            failed_count += 1
            scan_errors.append(error_entry(
                image_folder,
                scan_result.get("stage", "grype_scan"),
                "grype_scan_failed",
                scan_result.get("stderr") or "Grype scan failed",
                stdout=scan_result.get("stdout", ""),
                returncode=scan_result.get("returncode"),
            ))
            continue

        try:
            new_findings = deduplicate_findings(
                normalize_grype_data(load_json(vuln_path), metadata, image_folder)
            )
            
        except Exception as exc:
            failed_count += 1
            scan_errors.append(error_entry(image_folder, "json_parse", "invalid_new_grype_json", str(exc)))
            continue

        changes = compare_findings(old_findings, new_findings) if old_findings else {"new": new_findings, "changed": []}
        finding_changes["new"].extend(changes["new"])
        finding_changes["changed"].extend(changes["changed"])
        all_findings.extend(new_findings)
        scanned_count += 1

        if scan_result.get("table_returncode") not in (0, None):
            scan_errors.append(error_entry(
                image_folder,
                "grype_table_scan",
                "grype_table_output_failed",
                scan_result.get("table_stderr", "Failed to generate table output"),
                returncode=scan_result.get("table_returncode"),
            ))

   
    cve_index = build_cve_index(all_findings)
    image_index = build_image_index(all_findings)
    package_index = build_package_index(all_findings)
    
    finished_at = utc_now()
    monitor_run = {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "results_dir": str(results_dir),
        "monitoring_dir": str(monitoring_dir),
        "archived_previous_run_to": archived_to,
        "grype_version": grype_version,
        "grype_db": grype_db,
        "total_folders_discovered": len(folders) + len(skipped),
        "valid_sbom_folders": len(folders),
        "scanned_count": scanned_count,
        "skipped_count": len(skipped),
        "failed_count": failed_count,
        "finding_count": len(all_findings),
        "new_finding_count": len(finding_changes["new"]),
        "changed_finding_count": len(finding_changes["changed"]),
        "cve_index_count": len(cve_index),
        "image_index_count": len(image_index),
        "package_index_count": len(package_index),
        "error_count": len(scan_errors),
    }

    monitoring_overview = build_monitoring_overview(
        monitor_run=monitor_run,
        findings=all_findings,
        finding_changes=finding_changes,
        cve_index=cve_index,
        image_index=image_index,
        package_index=package_index,
        scan_errors=scan_errors,
    )
    
    monitoring_report = build_monitoring_report(monitoring_overview)
 

    write_json(current_dir / "findings" / "current-findings.json", all_findings)
    write_json(current_dir / "findings" / "finding-changes.json", finding_changes)

    write_json(current_dir / "indexes" / "by-cve.json", cve_index)
    write_json(current_dir / "indexes" / "by-image.json", image_index)
    write_json(current_dir / "indexes" / "by-package.json", package_index)

    write_json(current_dir / "reports" / "overview.json", monitoring_overview)
    write_text(current_dir / "reports" / "report.md", monitoring_report)

    write_json(current_dir / "run" / "run-errors.json", scan_errors)
    write_json(current_dir / "run" / "run-metadata.json", monitor_run)

    print(
        f"SBOM monitor completed: scanned={scanned_count}, skipped={len(skipped)}, "
        f"failed={failed_count}, findings={len(all_findings)}, "
        f"new={len(finding_changes['new'])}, changed={len(finding_changes['changed'])}, "
        f"errors={len(scan_errors)}"
    )


if __name__ == "__main__":
    main()
