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


def _image_label(image):
    return (
        image.get("image_reference")
        or image.get("image_name")
        or image.get("image_digest")
        or image.get("image_folder")
        or ""
    )


def _images_text(images):
    return ", ".join(_image_label(image) for image in images or [])


def _has_fix_versions(item):
    return bool(item.get("fixed_versions"))


def _build_fixable_cve_rows(cves):
    rows = []

    for cve in cves:
        for package in cve.get("affected_packages", []):
            if not _has_fix_versions(package):
                continue

            rows.append([
                cve.get("vulnerability_id"),
                package.get("severity") or cve.get("severity"),
                package.get("package_name"),
                package.get("package_version"),
                package.get("package_type"),
                package.get("fixed_versions", []),
                package.get("affected_image_count", 0),
                _images_text(package.get("affected_images", [])),
            ])

    return rows


def _build_non_fixable_cve_rows(cves):
    rows = []

    for cve in cves:
        for package in cve.get("affected_packages", []):
            if _has_fix_versions(package):
                continue

            rows.append([
                cve.get("vulnerability_id"),
                package.get("severity") or cve.get("severity"),
                package.get("package_name"),
                package.get("package_version"),
                package.get("package_type"),
                package.get("fix_state"),
                package.get("affected_image_count", 0),
                _images_text(package.get("affected_images", [])),
            ])

    return rows


def _build_fixable_package_rows(packages):
    rows = []

    for package in packages:
        for vulnerability in package.get("vulnerabilities", []):
            if not _has_fix_versions(vulnerability):
                continue

            rows.append([
                package.get("package_name"),
                package.get("package_version"),
                package.get("package_type"),
                vulnerability.get("vulnerability_id"),
                vulnerability.get("severity") or package.get("severity"),
                vulnerability.get("fixed_versions", []),
                vulnerability.get("affected_image_count", 0),
                _images_text(vulnerability.get("affected_images", [])),
            ])

    return rows


def _build_non_fixable_package_rows(packages):
    rows = []

    for package in packages:
        for vulnerability in package.get("vulnerabilities", []):
            if _has_fix_versions(vulnerability):
                continue

            rows.append([
                package.get("package_name"),
                package.get("package_version"),
                package.get("package_type"),
                vulnerability.get("vulnerability_id"),
                vulnerability.get("severity") or package.get("severity"),
                vulnerability.get("fix_state"),
                vulnerability.get("affected_image_count", 0),
                _images_text(vulnerability.get("affected_images", [])),
            ])

    return rows


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

    fixable_cve_rows = _build_fixable_cve_rows(cves)
    non_fixable_cve_rows = _build_non_fixable_cve_rows(cves)

    fixable_package_rows = _build_fixable_package_rows(packages)
    non_fixable_package_rows = _build_non_fixable_package_rows(packages)

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

## Fixable CVEs

{_table(
    ["CVE", "Severity", "Package", "Installed Version", "Package Type", "Fixed Versions", "Affected Images", "Images"],
    fixable_cve_rows,
)}

## Non-Fixable / Unknown-Fix CVEs

{_table(
    ["CVE", "Severity", "Package", "Installed Version", "Package Type", "Fix State", "Affected Images", "Images"],
    non_fixable_cve_rows,
)}

## Fixable Packages

{_table(
    ["Package", "Installed Version", "Package Type", "CVE", "Severity", "Fixed Versions", "Affected Images", "Images"],
    fixable_package_rows,
)}

## Non-Fixable / Unknown-Fix Packages

{_table(
    ["Package", "Installed Version", "Package Type", "CVE", "Severity", "Fix State", "Affected Images", "Images"],
    non_fixable_package_rows,
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
