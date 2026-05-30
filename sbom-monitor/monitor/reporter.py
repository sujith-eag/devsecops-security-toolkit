def _value(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def _escape(value):
    return _value(value).replace("|", "\\|").replace("\n", " ")


def _table(headers, rows):
    if not rows:
        return "_None_\n"

    header_line = "| " + " | ".join(headers) + " |"
    separator = "| " + " | ".join(["---"] * len(headers)) + " |"
    row_lines = [
        "| " + " | ".join(_escape(cell) for cell in row) + " |"
        for row in rows
    ]

    return "\n".join([header_line, separator, *row_lines]) + "\n"


def _severity_text(counts):
    return (
        f"Critical={counts.get('Critical', 0)}, "
        f"High={counts.get('High', 0)}, "
        f"Medium={counts.get('Medium', 0)}, "
        f"Low={counts.get('Low', 0)}, "
        f"Negligible={counts.get('Negligible', 0)}, "
        f"Unknown={counts.get('Unknown', 0)}"
    )


def _format_changes(changes):
    if not changes:
        return ""
    return "; ".join(
        f"{field}: {detail.get('old')} → {detail.get('new')}"
        for field, detail in changes.items()
    )


def build_monitoring_report(overview):
    run = overview.get("run_summary", {})
    counts = overview.get("overall_counts", {})
    severity = overview.get("severity_summary", {})
    fixability = overview.get("fixability_summary", {})

    images = overview.get("images", [])
    cves = overview.get("cves", [])
    packages = overview.get("packages", [])
    new_findings = overview.get("new_findings", [])
    changed_findings = overview.get("changed_findings", [])
    scan_errors = overview.get("scan_errors", [])

    image_rows = [
        [
            item.get("image_reference") or item.get("image_name"),
            item.get("image_digest"),
            item.get("finding_count"),
            item.get("vulnerability_count"),
            item.get("package_count"),
            _severity_text(item.get("severity_counts", {})),
            item.get("fixable_count"),
        ]
        for item in images
    ]

    cve_rows = [
        [
            item.get("vulnerability_id"),
            item.get("severity"),
            item.get("finding_count"),
            item.get("affected_image_count"),
            item.get("affected_package_count"),
            item.get("fix_available"),
            item.get("fixed_versions", []),
        ]
        for item in cves
    ]

    package_rows = [
        [
            item.get("package_name"),
            item.get("package_version"),
            item.get("package_type"),
            item.get("severity"),
            item.get("finding_count"),
            item.get("vulnerability_count"),
            item.get("affected_image_count"),
            item.get("fix_available"),
            item.get("fixed_versions", []),
        ]
        for item in packages
    ]

    new_rows = [
        [
            item.get("vulnerability_id"),
            item.get("severity"),
            item.get("image_reference"),
            item.get("package_name"),
            item.get("package_version"),
            item.get("package_type"),
            item.get("fix_state"),
            item.get("fixed_versions", []),
        ]
        for item in new_findings
    ]

    changed_rows = [
        [
            item.get("vulnerability_id"),
            item.get("image_reference") or item.get("image_name"),
            item.get("package_name"),
            item.get("package_version"),
            item.get("package_type"),
            _format_changes(item.get("changes", {})),
        ]
        for item in changed_findings
    ]

    error_rows = [
        [
            item.get("image_folder"),
            item.get("stage"),
            item.get("error_type"),
            item.get("message"),
        ]
        for item in scan_errors
    ]

    return f"""# SBOM Monitoring Report

## Run Summary

| Field | Value |
| --- | --- |
| Run ID | {_escape(run.get("run_id"))} |
| Started At | {_escape(run.get("started_at"))} |
| Finished At | {_escape(run.get("finished_at"))} |
| Results Dir | {_escape(run.get("results_dir"))} |
| Images Scanned | {_escape(run.get("scanned_count"))} |
| Skipped | {_escape(run.get("skipped_count"))} |
| Failed | {_escape(run.get("failed_count"))} |
| Errors | {_escape(run.get("error_count"))} |

## Overall Counts

| Metric | Count |
| --- | --- |
| Findings | {counts.get("finding_count", 0)} |
| Unique CVEs | {counts.get("unique_cve_count", 0)} |
| Images | {counts.get("image_count", 0)} |
| Vulnerable Packages | {counts.get("vulnerable_package_count", 0)} |
| New Findings | {counts.get("new_finding_count", 0)} |
| Changed Findings | {counts.get("changed_finding_count", 0)} |
| Scan Errors | {counts.get("scan_error_count", 0)} |

## Severity Summary

| Severity | Count |
| --- | --- |
| Critical | {severity.get("Critical", 0)} |
| High | {severity.get("High", 0)} |
| Medium | {severity.get("Medium", 0)} |
| Low | {severity.get("Low", 0)} |
| Negligible | {severity.get("Negligible", 0)} |
| Unknown | {severity.get("Unknown", 0)} |

## Fixability Summary

| Metric | Count |
| --- | --- |
| Fixable Findings | {fixability.get("fixable_findings", 0)} |
| Not Fixable / Unknown | {fixability.get("not_fixable_or_unknown_findings", 0)} |

## Images Overview

{_table(
    ["Image", "Digest", "Findings", "CVEs", "Packages", "Severity Counts", "Fixable"],
    image_rows,
)}

## CVE Overview

{_table(
    ["CVE", "Severity", "Findings", "Images", "Packages", "Fix Available", "Fixed Versions"],
    cve_rows,
)}

## Package Overview

{_table(
    ["Package", "Version", "Type", "Severity", "Findings", "CVEs", "Images", "Fix Available", "Fixed Versions"],
    package_rows,
)}

## New Findings

{_table(
    ["CVE", "Severity", "Image", "Package", "Version", "Type", "Fix State", "Fixed Versions"],
    new_rows,
)}

## Changed Findings

{_table(
    ["CVE", "Image", "Package", "Version", "Type", "Changes"],
    changed_rows,
)}

## Scan Errors

{_table(
    ["Image Folder", "Stage", "Error Type", "Message"],
    error_rows,
)}
"""
