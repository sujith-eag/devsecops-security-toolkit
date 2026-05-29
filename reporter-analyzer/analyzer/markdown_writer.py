def write_markdown_report(summary, path):
    image = summary["image"]
    stats = summary["summary"]

    lines = []

    lines.append("**Container Image Security Analysis Report**")
    lines.append("")
    lines.append("**Image Details**")
    lines.append("")
    lines.append(f"- Image: `{image.get('image_ref', '')}`")
    lines.append(f"- Source: `{image.get('image_source', '')}`")
    lines.append(f"- Digest: `{image.get('digest_value', '')}`")
    lines.append(f"- OS/Architecture: `{image.get('image_os', '')}/{image.get('image_architecture', '')}`")
    lines.append(f"- Original scan time: `{image.get('scan_timestamp_utc', '')}`")
    lines.append(f"- Analysis generated at: `{summary.get('generated_at', '')}`")
    lines.append("")

    lines.append("**Summary**")
    lines.append("")
    lines.append(f"- Raw Grype matches: **{stats.get('raw_match_count', 0)}**")
    lines.append(f"- Unique findings: **{stats.get('unique_finding_count', 0)}**")
    lines.append(f"- Duplicate matches reduced: **{stats.get('duplicates_reduced', 0)}**")
    lines.append(f"- Fixable findings: **{stats.get('fixable_findings', 0)}**")
    lines.append(f"- Non-fixable findings: **{stats.get('non_fixable_findings', 0)}**")
    if stats.get("sbom_component_count") is not None:
        lines.append(f"- SBOM component count: **{stats.get('sbom_component_count')}**")
    lines.append("")

    lines.append("**Severity Counts**")
    lines.append("")
    for severity, count in stats.get("severity_counts", {}).items():
        lines.append(f"- {severity}: **{count}**")
    lines.append("")

    lines.append("**Top Affected Packages**")
    lines.append("")
    for item in summary.get("top_affected_packages", [])[:10]:
        lines.append(f"- `{item['name']}`: {item['count']} finding(s)")
    lines.append("")

    lines.append("**Remediation Area Counts**")
    lines.append("")
    for area, count in summary.get("remediation_area_counts", {}).items():
        lines.append(f"- `{area}`: {count}")
    lines.append("")

    lines.append("**Priority CVE Groups: Critical and High**")
    lines.append("")
    priority_groups = summary.get("priority_cve_groups", [])

    if not priority_groups:
        lines.append("No critical or high findings detected.")
    else:
        for group in priority_groups:
            affected_packages = group.get("affected_packages", [])
            package_display = ", ".join(affected_packages[:8])

            if len(affected_packages) > 8:
                package_display += f", and {len(affected_packages) - 8} more"

            actions = group.get("remediation_actions", [])
            action_display = actions[0] if actions else "Review affected packages and update where possible"

            lines.append(f"- **{group.get('severity')}** `{group.get('vulnerability_id')}`")
            lines.append(f"  - Affected packages: `{package_display}`")
            lines.append(f"  - Package findings grouped: **{group.get('finding_count', 0)}**")
            lines.append(f"  - Fix available: **{group.get('fix_available', False)}**")
            lines.append(f"  - Recommended action: {action_display}")
            lines.append("")


    if summary.get("warnings"):
        lines.append("**Warnings**")
        lines.append("")
        for warning in summary.get("warnings", []):
            lines.append(f"- {warning}")
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
