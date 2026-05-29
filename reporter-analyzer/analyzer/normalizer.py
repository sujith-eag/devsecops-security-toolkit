def normalize_matches(grype_json):
    records = []

    for match in grype_json.get("matches", []):
        vuln = match.get("vulnerability", {}) or {}
        artifact = match.get("artifact", {}) or {}

        fixed_versions = vuln.get("fix", {}).get("versions", []) or []
        locations = artifact.get("locations", []) or []

        records.append({
            "vulnerability_id": vuln.get("id", ""),
            "severity": vuln.get("severity", "Unknown"),
            "namespace": vuln.get("namespace", ""),
            "description": vuln.get("description", ""),
            "data_source": vuln.get("dataSource", ""),
            "package_name": artifact.get("name", ""),
            "package_version": artifact.get("version", ""),
            "package_type": artifact.get("type", ""),
            "artifact_id": artifact.get("id", ""),
            "artifact_purl": artifact.get("purl", ""),
            "fixed_versions": fixed_versions,
            "fix_available": bool(fixed_versions),
            "access_path": locations[0].get("accessPath", "") if locations else "",
        })

    return records
