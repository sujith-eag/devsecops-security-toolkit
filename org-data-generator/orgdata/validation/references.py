def validate_references(artifacts, packages, vulnerabilities, artifact_packages, findings):
    warnings = []
    artifact_ids = {item.get("artifact_id") for item in artifacts}
    package_ids = {item.get("package_id") for item in packages}
    vulnerability_ids = {item.get("vulnerability_id") for item in vulnerabilities}

    for rel in artifact_packages:
        if rel.get("artifact_id") not in artifact_ids:
            warnings.append({"stage": "reference_validation", "warning_type": "missing_artifact_reference", "relationship": "artifact-packages", "artifact_id": rel.get("artifact_id")})
        if rel.get("package_id") not in package_ids:
            warnings.append({"stage": "reference_validation", "warning_type": "missing_package_reference", "relationship": "artifact-packages", "package_id": rel.get("package_id")})

    for finding in findings:
        if finding.get("artifact_id") not in artifact_ids:
            warnings.append({"stage": "reference_validation", "warning_type": "missing_artifact_reference", "relationship": "findings", "artifact_id": finding.get("artifact_id"), "finding_id": finding.get("finding_id")})
        if finding.get("package_id") not in package_ids:
            warnings.append({"stage": "reference_validation", "warning_type": "missing_package_reference", "relationship": "findings", "package_id": finding.get("package_id"), "finding_id": finding.get("finding_id")})
        if finding.get("vulnerability_id") not in vulnerability_ids:
            warnings.append({"stage": "reference_validation", "warning_type": "missing_vulnerability_reference", "relationship": "findings", "vulnerability_id": finding.get("vulnerability_id"), "finding_id": finding.get("finding_id")})

    return warnings
