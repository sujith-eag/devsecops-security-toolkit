def parse_cyclonedx_components(sbom_data):
    components = sbom_data.get("components") or []
    if not isinstance(components, list):
        return []
    return components


def component_licenses(component):
    result = []
    for item in component.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        license_data = item.get("license") or {}
        if isinstance(license_data, dict):
            value = license_data.get("id") or license_data.get("name")
            if value and value not in result:
                result.append(value)
        elif isinstance(license_data, str) and license_data not in result:
            result.append(license_data)
    return result
