def apply_remediation(records):
    os_package_types = {"deb", "rpm", "apk"}
    app_package_types = {"npm", "pypi", "python", "java-archive", "maven", "gem", "go-module", "composer"}

    for record in records:
        package_type = (record.get("package_type") or "").lower()
        fixed_versions = record.get("fixed_versions", [])

        if package_type in os_package_types:
            record["remediation_area"] = "base-image-or-os-package"
        elif package_type in app_package_types:
            record["remediation_area"] = "application-dependency"
        else:
            record["remediation_area"] = "unknown-package-source"

        if fixed_versions:
            record["remediation_action"] = f"Upgrade package to fixed version: {', '.join(fixed_versions)}"
        else:
            record["remediation_action"] = "No fixed version available; review risk or wait for vendor fix"

    return records
