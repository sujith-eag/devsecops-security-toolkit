from orgdata.normalize.ids import normalize_package_type, package_id_from_values, package_type_from_purl

LANGUAGE_MAP = {
    "go": "golang",
    "javascript": "npm",
    "python": "python",
    "java": "maven",
    "ruby": "gem",
    "rust": "cargo",
    "dotnet": "nuget",
}

FOUND_BY_MAP = {
    "dpkg-db-cataloger": "deb",
    "apk-db-cataloger": "apk",
    "rpm-db-cataloger": "rpm",
    "go-module-binary-cataloger": "golang",
    "go-module-file-cataloger": "golang",
    "package-lock-cataloger": "npm",
    "npm-package-cataloger": "npm",
    "python-package-cataloger": "python",
    "java-archive-cataloger": "maven",
    "gemfile-cataloger": "gem",
}


def as_list(value):
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def merge_unique(existing, values):
    merged = list(existing or [])
    for value in as_list(values):
        if value not in (None, "") and value not in merged:
            merged.append(value)
    return merged


def component_properties(component):
    result = {}
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") and prop.get("value") not in (None, ""):
            result[prop["name"]] = prop["value"]
    return result


def component_licenses(component):
    result = []
    for item in component.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        lic = item.get("license") or {}
        value = lic.get("id") or lic.get("name") if isinstance(lic, dict) else lic
        if value and value not in result:
            result.append(value)
    return result


def package_type_from_component(component):
    purl = component.get("purl") or ""
    props = component_properties(component)
    from_purl = package_type_from_purl(purl)
    if from_purl:
        return normalize_package_type(from_purl)
    language = (props.get("syft:package:language") or "").lower()
    if language:
        return normalize_package_type(LANGUAGE_MAP.get(language, language))
    found_by = props.get("syft:package:foundBy") or ""
    if found_by in FOUND_BY_MAP:
        return normalize_package_type(FOUND_BY_MAP[found_by])
    return normalize_package_type(component.get("type") or "unknown")


def parse_components(sbom_data):
    components = sbom_data.get("components") or []
    return components if isinstance(components, list) else []


def normalize_component(component, artifact_id):
    component_type = component.get("type") or ""
    if component_type in ("file", "operating-system"):
        return None, None

    name = str(component.get("name") or "")
    if not name:
        return None, None

    version = str(component.get("version") or "")
    purl = str(component.get("purl") or "")
    package_type = package_type_from_component(component)
    package_id = package_id_from_values(purl, package_type, name, version)
    bom_ref = str(component.get("bom-ref") or component.get("bomRef") or "")

    package = {
        "package_id": package_id,
        "package_name": name,
        "package_version": version,
        "package_type": package_type,
        "package_group": str(component.get("group") or ""),
        "component_type": component_type,
        "normalized_purl": package_id if str(package_id).startswith("pkg:") else "",
        "purls": as_list(purl),
        "licenses": component_licenses(component),
        "publisher": str(component.get("publisher") or ""),
    }

    relationship = {
        "artifact_id": artifact_id,
        "package_id": package_id,
        "bom_refs": as_list(bom_ref),
        "purls": as_list(purl),
        "relationship_type": "contains",
        "duplicate_count": 1,
    }

    return package, relationship


def merge_package(existing, new):
    for field in ("package_name", "package_version", "package_type", "package_group", "component_type", "normalized_purl", "publisher"):
        if existing.get(field) in (None, "", []):
            existing[field] = new.get(field)
    existing["purls"] = merge_unique(existing.get("purls"), new.get("purls"))
    existing["licenses"] = merge_unique(existing.get("licenses"), new.get("licenses"))
    return existing


def merge_artifact_package(existing, new):
    existing["bom_refs"] = merge_unique(existing.get("bom_refs"), new.get("bom_refs"))
    existing["purls"] = merge_unique(existing.get("purls"), new.get("purls"))
    existing["duplicate_count"] = existing.get("duplicate_count", 1) + new.get("duplicate_count", 1)
    return existing
