SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]


def _fix_available(finding):
    return bool(finding.get("fixed_versions")) or finding.get("fix_state") == "fixed"


def _severity_counts(findings):
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = finding.get("severity") or "Unknown"
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _fixability_summary(findings):
    fixable = [item for item in findings if _fix_available(item)]
    not_fixable = [item for item in findings if not _fix_available(item)]

    return {
        "fixable_findings": len(fixable),
        "not_fixable_or_unknown_findings": len(not_fixable),
        "fixable_by_severity": _severity_counts(fixable),
        "not_fixable_or_unknown_by_severity": _severity_counts(not_fixable),
    }


def build_monitoring_overview(
    monitor_run,
    findings,
    finding_changes,
    cve_index,
    image_index,
    package_index,
    scan_errors,
):
    return {
        "run_summary": {
            "run_id": monitor_run.get("run_id"),
            "started_at": monitor_run.get("started_at"),
            "finished_at": monitor_run.get("finished_at"),
            "results_dir": monitor_run.get("results_dir"),
            "scanned_count": monitor_run.get("scanned_count", 0),
            "skipped_count": monitor_run.get("skipped_count", 0),
            "failed_count": monitor_run.get("failed_count", 0),
            "error_count": monitor_run.get("error_count", 0),
        },
        "overall_counts": {
            "finding_count": len(findings),
            "unique_cve_count": len(cve_index),
            "image_count": len(image_index),
            "vulnerable_package_count": len(package_index),
            "new_finding_count": len(finding_changes.get("new", [])),
            "changed_finding_count": len(finding_changes.get("changed", [])),
            "scan_error_count": len(scan_errors),
        },
        "severity_summary": _severity_counts(findings),
        "fixability_summary": _fixability_summary(findings),
        "images": image_index,
        "cves": cve_index,
        "packages": package_index,
        "new_findings": finding_changes.get("new", []),
        "changed_findings": finding_changes.get("changed", []),
        "scan_errors": scan_errors,
    }
