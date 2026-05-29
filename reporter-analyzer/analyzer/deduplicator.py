def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def _merge_unique(existing, new_values):
    merged = list(existing or [])
    for value in _as_list(new_values):
        if value and value not in merged:
            merged.append(value)
    return merged


def deduplicate_records(records):
    deduped = {}

    for record in records:
        key = (
            record.get("vulnerability_id", ""),
            record.get("package_name", ""),
            record.get("package_version", ""),
            record.get("package_type", ""),
        )

        if key not in deduped:
            item = dict(record)
            item["access_paths"] = _as_list(record.get("access_path"))
            item["artifact_ids"] = _as_list(record.get("artifact_id"))
            item["artifact_purls"] = _as_list(record.get("artifact_purl"))
            item["data_sources"] = _as_list(record.get("data_source"))
            item["namespaces"] = _as_list(record.get("namespace"))
            item["duplicate_count"] = 1

            item.pop("access_path", None)
            item.pop("artifact_id", None)
            item.pop("artifact_purl", None)
            item.pop("data_source", None)
            item.pop("namespace", None)

            deduped[key] = item
            continue

        item = deduped[key]
        item["access_paths"] = _merge_unique(item.get("access_paths"), record.get("access_path"))
        item["artifact_ids"] = _merge_unique(item.get("artifact_ids"), record.get("artifact_id"))
        item["artifact_purls"] = _merge_unique(item.get("artifact_purls"), record.get("artifact_purl"))
        item["data_sources"] = _merge_unique(item.get("data_sources"), record.get("data_source"))
        item["namespaces"] = _merge_unique(item.get("namespaces"), record.get("namespace"))
        item["fixed_versions"] = _merge_unique(item.get("fixed_versions"), record.get("fixed_versions"))
        item["duplicate_count"] = item.get("duplicate_count", 1) + 1
        item["fix_available"] = bool(item.get("fixed_versions"))

    return list(deduped.values())
