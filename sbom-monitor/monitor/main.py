import argparse
import uuid
from datetime import datetime, timezone
from pathlib import Path

from monitor.archive import archive_current
from monitor.comparator import compare_findings
from monitor.discovery import discover_result_folders
from monitor.grype_runner import get_grype_version, scan_sbom, update_grype_db
from monitor.normalizer import load_json, normalize_grype_data
from monitor.writer import write_json


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
                old_findings = normalize_grype_data(load_json(vuln_path), metadata, image_folder)
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
            new_findings = normalize_grype_data(load_json(vuln_path), metadata, image_folder)
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

    finished_at = utc_now()
    monitor_run = {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "results_dir": str(results_dir),
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
        "error_count": len(scan_errors),
    }

    write_json(current_dir / "findings.json", all_findings)
    write_json(current_dir / "finding-changes.json", finding_changes)
    write_json(current_dir / "scan-errors.json", scan_errors)
    write_json(current_dir / "monitor-run.json", monitor_run)

    print(
        f"SBOM monitor completed: scanned={scanned_count}, skipped={len(skipped)}, "
        f"failed={failed_count}, findings={len(all_findings)}, "
        f"new={len(finding_changes['new'])}, changed={len(finding_changes['changed'])}, "
        f"errors={len(scan_errors)}"
    )


if __name__ == "__main__":
    main()
