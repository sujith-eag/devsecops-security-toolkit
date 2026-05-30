SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Negligible": 1,
    "Unknown": 0,
}


def _severity_rank(severity):
    return SEVERITY_ORDER.get(severity or "Unknown", 0)


def _highest_severity(values):
    if not values:
        return "Unknown"
    return sorted(values, key=_severity_rank, reverse=True)[0]


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


def _severity_counts(findings):
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Negligible": 0,
        "Unknown": 0,
    }

    for finding in findings:
        severity = finding.get("severity") or "Unknown"
        if severity not in counts:
            counts[severity] = 0
        counts[severity] += 1

    return counts


def _fix_available(finding):
    return bool(finding.get("fixed_versions")) or finding.get("fix_state") == "fixed"


def _image_ref(finding):
    return {
        "image_digest": finding.get("image_digest", ""),
        "image_reference": finding.get("image_reference", ""),
        "image_name": finding.get("image_name", ""),
        "image_tag": finding.get("image_tag", ""),
        "image_folder": finding.get("image_folder", ""),
    }


def _package_ref(finding):
    return {
        "package_name": finding.get("package_name", ""),
        "package_version": finding.get("package_version", ""),
        "package_type": finding.get("package_type", ""),
    }


def _vulnerability_ref(finding):
    return {
        "vulnerability_id": finding.get("vulnerability_id", ""),
        "severity": finding.get("severity", "Unknown"),
        "fix_state": finding.get("fix_state", "unknown"),
        "fixed_versions": finding.get("fixed_versions", []),
    }


def build_cve_index(findings):
    grouped = {}

    for finding in findings:
        cve = finding.get("vulnerability_id", "")
        if not cve:
            continue

        if cve not in grouped:
            grouped[cve] = {
                "vulnerability_id": cve,
                "severity": finding.get("severity", "Unknown"),
                "severity_counts": {},
                "fix_available": False,
                "fixed_versions": [],
                "affected_image_count": 0,
                "affected_package_count": 0,
                "finding_count": 0,
                "affected_images": [],
                "affected_packages": [],
                "_image_keys": set(),
                "_package_keys": set(),
                "_findings": [],
            }

        item = grouped[cve]
        item["_findings"].append(finding)
        item["finding_count"] += 1
        item["severity"] = _highest_severity([item["severity"], finding.get("severity", "Unknown")])
        item["fix_available"] = item["fix_available"] or _fix_available(finding)
        item["fixed_versions"] = _merge_unique(item["fixed_versions"], finding.get("fixed_versions"))

        image_key = finding.get("image_digest", "") or finding.get("image_folder", "")
        if image_key not in item["_image_keys"]:
            item["_image_keys"].add(image_key)
            item["affected_images"].append(_image_ref(finding))

        package_key = "|".join([
            finding.get("package_name", ""),
            finding.get("package_version", ""),
            finding.get("package_type", ""),
        ])
        if package_key not in item["_package_keys"]:
            item["_package_keys"].add(package_key)
            item["affected_packages"].append(_package_ref(finding))

    result = []
    for item in grouped.values():
        item["severity_counts"] = _severity_counts(item.pop("_findings"))
        item["affected_image_count"] = len(item["_image_keys"])
        item["affected_package_count"] = len(item["_package_keys"])
        item.pop("_image_keys", None)
        item.pop("_package_keys", None)

        item["affected_images"] = sorted(
            item["affected_images"],
            key=lambda value: value.get("image_reference") or value.get("image_digest"),
        )
        item["affected_packages"] = sorted(
            item["affected_packages"],
            key=lambda value: (
                value.get("package_name", ""),
                value.get("package_version", ""),
                value.get("package_type", ""),
            ),
        )
        item["fixed_versions"] = sorted(item["fixed_versions"])
        result.append(item)

    return sorted(result, key=lambda item: (-_severity_rank(item["severity"]), item["vulnerability_id"]))


def build_image_index(findings):
    grouped = {}

    for finding in findings:
        image_key = finding.get("image_digest", "") or finding.get("image_folder", "")
        if not image_key:
            continue

        if image_key not in grouped:
            grouped[image_key] = {
                **_image_ref(finding),
                "finding_count": 0,
                "vulnerability_count": 0,
                "package_count": 0,
                "fixable_count": 0,
                "severity_counts": {},
                "vulnerabilities": [],
                "affected_packages": [],
                "_vulnerability_keys": set(),
                "_package_keys": set(),
                "_findings": [],
            }

        item = grouped[image_key]
        item["_findings"].append(finding)
        item["finding_count"] += 1

        if _fix_available(finding):
            item["fixable_count"] += 1

        cve = finding.get("vulnerability_id", "")
        if cve and cve not in item["_vulnerability_keys"]:
            item["_vulnerability_keys"].add(cve)
            item["vulnerabilities"].append(_vulnerability_ref(finding))

        package_key = "|".join([
            finding.get("package_name", ""),
            finding.get("package_version", ""),
            finding.get("package_type", ""),
        ])
        if package_key not in item["_package_keys"]:
            item["_package_keys"].add(package_key)
            item["affected_packages"].append(_package_ref(finding))

    result = []
    for item in grouped.values():
        item["severity_counts"] = _severity_counts(item.pop("_findings"))
        item["vulnerability_count"] = len(item["_vulnerability_keys"])
        item["package_count"] = len(item["_package_keys"])
        item.pop("_vulnerability_keys", None)
        item.pop("_package_keys", None)

        item["vulnerabilities"] = sorted(
            item["vulnerabilities"],
            key=lambda value: (-_severity_rank(value.get("severity")), value.get("vulnerability_id", "")),
        )
        item["affected_packages"] = sorted(
            item["affected_packages"],
            key=lambda value: (
                value.get("package_name", ""),
                value.get("package_version", ""),
                value.get("package_type", ""),
            ),
        )
        result.append(item)

    return sorted(result, key=lambda item: (-item["finding_count"], item.get("image_reference") or item.get("image_digest")))


def build_package_index(findings):
    grouped = {}

    for finding in findings:
        package_key = "|".join([
            finding.get("package_name", ""),
            finding.get("package_version", ""),
            finding.get("package_type", ""),
        ])
        if not package_key.strip("|"):
            continue

        if package_key not in grouped:
            grouped[package_key] = {
                **_package_ref(finding),
                "finding_count": 0,
                "vulnerability_count": 0,
                "affected_image_count": 0,
                "fix_available": False,
                "fixed_versions": [],
                "severity": finding.get("severity", "Unknown"),
                "severity_counts": {},
                "vulnerabilities": [],
                "affected_images": [],
                "_vulnerability_keys": set(),
                "_image_keys": set(),
                "_findings": [],
            }

        item = grouped[package_key]
        item["_findings"].append(finding)
        item["finding_count"] += 1
        item["severity"] = _highest_severity([item["severity"], finding.get("severity", "Unknown")])
        item["fix_available"] = item["fix_available"] or _fix_available(finding)
        item["fixed_versions"] = _merge_unique(item["fixed_versions"], finding.get("fixed_versions"))

        cve = finding.get("vulnerability_id", "")
        if cve and cve not in item["_vulnerability_keys"]:
            item["_vulnerability_keys"].add(cve)
            item["vulnerabilities"].append(_vulnerability_ref(finding))

        image_key = finding.get("image_digest", "") or finding.get("image_folder", "")
        if image_key not in item["_image_keys"]:
            item["_image_keys"].add(image_key)
            item["affected_images"].append(_image_ref(finding))

    result = []
    for item in grouped.values():
        item["severity_counts"] = _severity_counts(item.pop("_findings"))
        item["vulnerability_count"] = len(item["_vulnerability_keys"])
        item["affected_image_count"] = len(item["_image_keys"])
        item.pop("_vulnerability_keys", None)
        item.pop("_image_keys", None)

        item["vulnerabilities"] = sorted(
            item["vulnerabilities"],
            key=lambda value: (-_severity_rank(value.get("severity")), value.get("vulnerability_id", "")),
        )
        item["affected_images"] = sorted(
            item["affected_images"],
            key=lambda value: value.get("image_reference") or value.get("image_digest"),
        )
        item["fixed_versions"] = sorted(item["fixed_versions"])
        result.append(item)

    return sorted(result, key=lambda item: (-_severity_rank(item["severity"]), -item["affected_image_count"], item["package_name"]))
