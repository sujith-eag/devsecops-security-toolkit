def _merge_unique(existing, values):
    merged = list(existing or [])
    if values is None:
        return merged
    if not isinstance(values, list):
        values = [values]
    for value in values:
        if value not in (None, "") and value not in merged:
            merged.append(value)
    return merged


def _image_ref(record):
    return {
        "image_digest": record.get("image_digest", ""),
        "image_reference": record.get("image_reference", ""),
        "image_name": record.get("image_name", ""),
        "image_tag": record.get("image_tag", ""),
        "image_folder": record.get("image_folder", ""),
    }


def _package_ref(record):
    return {
        "package_name": record.get("package_name", ""),
        "package_version": record.get("package_version", ""),
        "package_type": record.get("package_type", ""),
        "package_group": record.get("package_group", ""),
        "purl": record.get("purl", ""),
        "licenses": record.get("licenses", []),
    }


def build_package_usage(records):
    grouped = {}

    for record in records:
        package_key = record.get("package_key", "")
        version = record.get("package_version", "")
        image_key = record.get("image_digest", "") or record.get("image_folder", "")

        if not package_key:
            continue

        if package_key not in grouped:
            grouped[package_key] = {
                "package_key": package_key,
                "package_name": record.get("package_name", ""),
                "package_type": record.get("package_type", ""),
                "package_groups": [],
                "used_version_count": 0,
                "total_image_count": 0,
                "used_versions": [],
                "_versions": {},
                "_image_keys": set(),
            }

        item = grouped[package_key]
        item["package_groups"] = _merge_unique(item.get("package_groups"), record.get("package_group"))
        item["_image_keys"].add(image_key)

        if version not in item["_versions"]:
            item["_versions"][version] = {
                "package_version": version,
                "package_version_key": record.get("package_version_key", ""),
                "image_count": 0,
                "images": [],
                "purls": [],
                "licenses": [],
                "_image_keys": set(),
            }

        version_item = item["_versions"][version]
        version_item["purls"] = _merge_unique(version_item.get("purls"), record.get("purls") or record.get("purl"))
        version_item["licenses"] = _merge_unique(version_item.get("licenses"), record.get("licenses"))
        if image_key and image_key not in version_item["_image_keys"]:
            version_item["_image_keys"].add(image_key)
            version_item["images"].append(_image_ref(record))

    result = []
    for item in grouped.values():
        versions = []
        for version_item in item.pop("_versions").values():
            version_item["image_count"] = len(version_item["_image_keys"])
            version_item["images"] = sorted(version_item["images"], key=lambda x: x.get("image_reference") or x.get("image_digest"))
            version_item["purls"] = sorted(version_item["purls"])
            version_item["licenses"] = sorted(version_item["licenses"])
            version_item.pop("_image_keys", None)
            versions.append(version_item)

        item["used_versions"] = sorted(versions, key=lambda x: x.get("package_version", ""))
        item["used_version_count"] = len(item["used_versions"])
        item["total_image_count"] = len(item["_image_keys"])
        item["package_groups"] = sorted(item["package_groups"])
        item.pop("_image_keys", None)
        result.append(item)

    return sorted(result, key=lambda x: (-x.get("total_image_count", 0), x.get("package_name", ""), x.get("package_type", "")))


def build_image_packages(records):
    grouped = {}

    for record in records:
        image_key = record.get("image_digest", "") or record.get("image_folder", "")
        package_version_key = record.get("package_version_key", "")
        if not image_key:
            continue

        if image_key not in grouped:
            grouped[image_key] = {
                **_image_ref(record),
                "package_count": 0,
                "package_type_counts": {},
                "packages": [],
                "_package_keys": set(),
            }

        item = grouped[image_key]
        if package_version_key and package_version_key not in item["_package_keys"]:
            item["_package_keys"].add(package_version_key)
            package = _package_ref(record)
            item["packages"].append(package)
            package_type = record.get("package_type") or "unknown"
            item["package_type_counts"][package_type] = item["package_type_counts"].get(package_type, 0) + 1

    result = []
    for item in grouped.values():
        item["package_count"] = len(item["_package_keys"])
        item["packages"] = sorted(
            item["packages"],
            key=lambda x: (x.get("package_name", ""), x.get("package_version", ""), x.get("package_type", "")),
        )
        item.pop("_package_keys", None)
        result.append(item)

    return sorted(result, key=lambda x: (-x.get("package_count", 0), x.get("image_reference") or x.get("image_digest")))
