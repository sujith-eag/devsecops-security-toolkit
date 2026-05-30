CHANGE_FIELDS = ("severity", "fix_state", "fixed_versions")


def compare_findings(old_findings, new_findings):
    old_by_key = {item["finding_key"]: item for item in old_findings}
    new_by_key = {item["finding_key"]: item for item in new_findings}

    new_items = [new_by_key[key] for key in sorted(set(new_by_key) - set(old_by_key))]
    changed_items = []

    for key in sorted(set(old_by_key) & set(new_by_key)):
        old_item = old_by_key[key]
        new_item = new_by_key[key]
        changes = {}
        for field in CHANGE_FIELDS:
            if old_item.get(field) != new_item.get(field):
                changes[field] = {
                    "old": old_item.get(field),
                    "new": new_item.get(field),
                }
        if changes:
            changed_items.append({
                "finding_key": key,
                "image_folder": new_item.get("image_folder", ""),
                "image_name": new_item.get("image_name", ""),
                "image_tag": new_item.get("image_tag", ""),
                "image_digest": new_item.get("image_digest", ""),
                "vulnerability_id": new_item.get("vulnerability_id", ""),
                "package_name": new_item.get("package_name", ""),
                "package_version": new_item.get("package_version", ""),
                "package_type": new_item.get("package_type", ""),
                "changes": changes,
            })

    return {"new": new_items, "changed": changed_items}
