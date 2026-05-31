def validate_artifact_references(artifact_id, artifact_package_ids, findings):
    warnings = []
    for finding in findings:
        if finding.get("package_id") not in artifact_package_ids:
            warnings.append({
                "artifact_id": artifact_id,
                "finding_id": finding.get("finding_id"),
                "package_id": finding.get("package_id"),
                "vulnerability_id": finding.get("vulnerability_id"),
                "stage": "reference_validation",
                "warning_type": "finding_package_not_found_in_artifact_packages",
                "message": "Finding package_id was not found in artifact-package relationships for this artifact.",
            })
    return warnings
