from inventory.sbom.parser import component_licenses


def first_present(data, keys, default=""):
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return default


def image_info(metadata: dict, image_folder: str):
    image_ref = first_present(metadata, ["image_reference", "image_ref", "image", "reference", "original_image"], "")
    image_name = first_present(metadata, ["image_name", "name", "repository", "repo"], "")
    image_tag = first_present(metadata, ["image_tag", "tag"], "")
    image_digest = first_present(metadata, ["image_digest", "digest", "digest_value", "repo_digest", "id", "image_id"], "")

    if not image_name and image_ref:
        image_name = image_ref.split("@")[0].rsplit(":", 1)[0]
    if not image_tag and image_ref and ":" in image_ref and "@" not in image_ref:
        image_tag = image_ref.rsplit(":", 1)[-1]

    return {
        "image_folder": image_folder,
        "image_reference": image_ref,
        "image_name": image_name,
        "image_tag": image_tag,
        "image_digest": image_digest or image_folder,
    }


def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def _merge_unique(existing, values):
    merged = list(existing or [])
    for value in _as_list(values):
        if value not in (None, "") and value not in merged:
            merged.append(value)
    return merged


def _component_properties(component):
    result = {}
    for prop in component.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        name = prop.get("name")
        value = prop.get("value")
        if name and value not in (None, ""):
            result[name] = value
    return result


def _package_type_from_purl(purl):
    if not purl or not isinstance(purl, str):
        return ""

    if not purl.startswith("pkg:"):
        return ""

    remainder = purl[4:]
    if "/" not in remainder:
        return remainder.split("@", 1)[0].split("?", 1)[0]

    return remainder.split("/", 1)[0]


def _package_type_from_syft_properties(properties):
    language = properties.get("syft:package:language", "")
    found_by = properties.get("syft:package:foundBy", "")

    if language:
        language_map = {
            "go": "golang",
            "javascript": "npm",
            "python": "python",
            "java": "maven",
            "ruby": "gem",
            "rust": "cargo",
            "dotnet": "nuget",
        }
        return language_map.get(language.lower(), language.lower())

    found_by_map = {
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

    return found_by_map.get(found_by, "")


def extract_package_type(component):
    component_type = str(component.get("type") or "")
    purl = str(component.get("purl") or "")
    properties = _component_properties(component)

    return (
        _package_type_from_purl(purl)
        or _package_type_from_syft_properties(properties)
        or component_type
        or "unknown"
    )


def normalize_component(component: dict, metadata: dict, image_folder: str):
    info = image_info(metadata, image_folder)

    component_type = str(component.get("type") or "")
    package_name = str(component.get("name") or "")
    package_version = str(component.get("version") or "")
    package_type = extract_package_type(component)
    package_group = str(component.get("group") or "")
    purl = str(component.get("purl") or "")
    bom_ref = str(component.get("bom-ref") or component.get("bomRef") or "")
    publisher = str(component.get("publisher") or "")

    package_key = "|".join([package_type, package_name])
    package_version_key = "|".join([package_type, package_name, package_version])
    usage_key = "|".join([info["image_digest"], package_type, package_name, package_version])

    return {
        "usage_key": usage_key,
        "package_key": package_key,
        "package_version_key": package_version_key,
        "package_name": package_name,
        "package_version": package_version,
        "package_type": package_type,
        "package_group": package_group,
        "purl": purl,
        "purls": _as_list(purl),
        "bom_ref": bom_ref,
        "bom_refs": _as_list(bom_ref),
        "component_type": component_type,
        "publisher": publisher,
        "licenses": component_licenses(component),
        **info,
    }


def deduplicate_package_usages(records):
    deduped = {}

    for record in records:
        key = record.get("usage_key", "")
        if not key:
            continue

        if key not in deduped:
            item = dict(record)
            item["duplicate_count"] = 1
            deduped[key] = item
            continue

        item = deduped[key]
        item["duplicate_count"] = item.get("duplicate_count", 1) + 1
        item["purls"] = _merge_unique(item.get("purls"), record.get("purl"))
        item["bom_refs"] = _merge_unique(item.get("bom_refs"), record.get("bom_ref"))
        item["licenses"] = _merge_unique(item.get("licenses"), record.get("licenses"))

        if not item.get("purl") and record.get("purl"):
            item["purl"] = record.get("purl")
        if not item.get("bom_ref") and record.get("bom_ref"):
            item["bom_ref"] = record.get("bom_ref")
        if not item.get("publisher") and record.get("publisher"):
            item["publisher"] = record.get("publisher")

    return sorted(
        deduped.values(),
        key=lambda item: (
            item.get("package_type", ""),
            item.get("package_name", ""),
            item.get("package_version", ""),
            item.get("image_reference", ""),
        ),
    )
