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
    values = [value or "Unknown" for value in values]
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
        counts[severity] = counts.get(severity, 0) + 1

    return counts


def _fix_available(finding):
    return bool(finding.get("fixed_versions"))


def _image_key(finding):
    return finding.get("image_digest", "") or finding.get("image_folder", "")


def _package_key(finding):
    return "|".join([
        finding.get("package_name", ""),
        finding.get("package_version", ""),
        finding.get("package_type", ""),
    ])


def _cve_key(finding):
    return finding.get("vulnerability_id", "")


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


def _sort_images(images):
    return sorted(
        images,
        key=lambda item: item.get("image_reference") or item.get("image_digest") or item.get("image_folder", ""),
    )


def _sort_packages(packages):
    return sorted(
        packages,
        key=lambda item: (
            item.get("package_name", ""),
            item.get("package_version", ""),
            item.get("package_type", ""),
        ),
    )


def _sort_vulnerabilities(vulnerabilities):
    return sorted(
        vulnerabilities,
        key=lambda item: (
            -_severity_rank(item.get("severity")),
            item.get("vulnerability_id", ""),
        ),
    )


def _build_package_groups_for_cve(findings):
    grouped = {}

    for finding in findings:
        key = _package_key(finding)

        if key not in grouped:
            grouped[key] = {
                **_package_ref(finding),
                "severity": finding.get("severity", "Unknown"),
                "fix_state": finding.get("fix_state", "unknown"),
                "fix_available": False,
                "fixed_versions": [],
                "finding_count": 0,
                "affected_image_count": 0,
                "affected_images": [],
                "_image_keys": set(),
            }

        item = grouped[key]
        item["finding_count"] += 1
        item["severity"] = _highest_severity([item["severity"], finding.get("severity", "Unknown")])
        item["fixed_versions"] = _merge_unique(item["fixed_versions"], finding.get("fixed_versions"))
        item["fix_available"] = item["fix_available"] or _fix_available(finding)

        if item.get("fix_state") != "fixed" and finding.get("fix_state") == "fixed":
            item["fix_state"] = "fixed"

        image_key = _image_key(finding)
        if image_key and image_key not in item["_image_keys"]:
            item["_image_keys"].add(image_key)
            item["affected_images"].append(_image_ref(finding))

    result = []
    for item in grouped.values():
        item["affected_image_count"] = len(item["_image_keys"])
        item["affected_images"] = _sort_images(item["affected_images"])
        item["fixed_versions"] = sorted(item["fixed_versions"])
        item.pop("_image_keys", None)
        result.append(item)

    return _sort_packages(result)


def _build_vulnerability_groups_for_package(findings):
    grouped = {}

    for finding in findings:
        key = _cve_key(finding)

        if key not in grouped:
            grouped[key] = {
                "vulnerability_id": finding.get("vulnerability_id", ""),
                "severity": finding.get("severity", "Unknown"),
                "fix_state": finding.get("fix_state", "unknown"),
                "fix_available": False,
                "fixed_versions": [],
                "finding_count": 0,
                "affected_image_count": 0,
                "affected_images": [],
                "_image_keys": set(),
            }

        item = grouped[key]
        item["finding_count"] += 1
        item["severity"] = _highest_severity([item["severity"], finding.get("severity", "Unknown")])
        item["fixed_versions"] = _merge_unique(item["fixed_versions"], finding.get("fixed_versions"))
        item["fix_available"] = item["fix_available"] or _fix_available(finding)

        if item.get("fix_state") != "fixed" and finding.get("fix_state") == "fixed":
            item["fix_state"] = "fixed"

        image_key = _image_key(finding)
        if image_key and image_key not in item["_image_keys"]:
            item["_image_keys"].add(image_key)
            item["affected_images"].append(_image_ref(finding))

    result = []
    for item in grouped.values():
        item["affected_image_count"] = len(item["_image_keys"])
        item["affected_images"] = _sort_images(item["affected_images"])
        item["fixed_versions"] = sorted(item["fixed_versions"])
        item.pop("_image_keys", None)
        result.append(item)

    return _sort_vulnerabilities(result)


def _build_vulnerability_groups_for_image(findings):
    grouped = {}

    for finding in findings:
        key = _cve_key(finding)

        if key not in grouped:
            grouped[key] = {
                "vulnerability_id": finding.get("vulnerability_id", ""),
                "severity": finding.get("severity", "Unknown"),
                "fix_available": False,
                "fixed_versions": [],
                "finding_count": 0,
                "affected_packages": [],
                "_package_keys": set(),
            }

        item = grouped[key]
        item["finding_count"] += 1
        item["severity"] = _highest_severity([item["severity"], finding.get("severity", "Unknown")])
        item["fixed_versions"] = _merge_unique(item["fixed_versions"], finding.get("fixed_versions"))
        item["fix_available"] = item["fix_available"] or _fix_available(finding)

        package_key = _package_key(finding)
        if package_key not in item["_package_keys"]:
            item["_package_keys"].add(package_key)
            item["affected_packages"].append({
                **_package_ref(finding),
                "fix_state": finding.get("fix_state", "unknown"),
                "fix_available": _fix_available(finding),
                "fixed_versions": finding.get("fixed_versions", []),
            })

    result = []
    for item in grouped.values():
        item["affected_package_count"] = len(item["_package_keys"])
        item["affected_packages"] = _sort_packages(item["affected_packages"])
        item["fixed_versions"] = sorted(item["fixed_versions"])
        item.pop("_package_keys", None)
        result.append(item)

    return _sort_vulnerabilities(result)


def build_cve_index(findings):
    grouped = {}

    for finding in findings:
        cve = _cve_key(finding)
        if not cve:
            continue

        if cve not in grouped:
            grouped[cve] = {
                "vulnerability_id": cve,
                "severity": finding.get("severity", "Unknown"),
                "severity_counts": {},
                "fix_available": False,
                "fixed_versions": [],
                "finding_count": 0,
                "affected_image_count": 0,
                "affected_package_count": 0,
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

        image_key = _image_key(finding)
        if image_key and image_key not in item["_image_keys"]:
            item["_image_keys"].add(image_key)
            item["affected_images"].append(_image_ref(finding))

        package_key = _package_key(finding)
        if package_key and package_key not in item["_package_keys"]:
            item["_package_keys"].add(package_key)

    result = []
    for item in grouped.values():
        cve_findings = item.pop("_findings")
        item["severity_counts"] = _severity_counts(cve_findings)
        item["affected_image_count"] = len(item["_image_keys"])
        item["affected_package_count"] = len(item["_package_keys"])
        item["affected_images"] = _sort_images(item["affected_images"])
        item["affected_packages"] = _build_package_groups_for_cve(cve_findings)
        item["fixed_versions"] = sorted(item["fixed_versions"])
        item.pop("_image_keys", None)
        item.pop("_package_keys", None)
        result.append(item)

    return sorted(
        result,
        key=lambda item: (
            -_severity_rank(item["severity"]),
            item["vulnerability_id"],
        ),
    )


def build_image_index(findings):
    grouped = {}

    for finding in findings:
        image_key = _image_key(finding)
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

        cve = _cve_key(finding)
        if cve:
            item["_vulnerability_keys"].add(cve)

        package_key = _package_key(finding)
        if package_key and package_key not in item["_package_keys"]:
            item["_package_keys"].add(package_key)
            item["affected_packages"].append(_package_ref(finding))

    result = []
    for item in grouped.values():
        image_findings = item.pop("_findings")
        item["severity_counts"] = _severity_counts(image_findings)
        item["vulnerability_count"] = len(item["_vulnerability_keys"])
        item["package_count"] = len(item["_package_keys"])
        item["vulnerabilities"] = _build_vulnerability_groups_for_image(image_findings)
        item["affected_packages"] = _sort_packages(item["affected_packages"])
        item.pop("_vulnerability_keys", None)
        item.pop("_package_keys", None)
        result.append(item)

    return sorted(
        result,
        key=lambda item: (
            -item["finding_count"],
            item.get("image_reference") or item.get("image_digest") or item.get("image_folder", ""),
        ),
    )


def build_package_index(findings):
    grouped = {}

    for finding in findings:
        package_key = _package_key(finding)
        if not package_key.strip("|"):
            continue

        if package_key not in grouped:
            grouped[package_key] = {
                **_package_ref(finding),
                "severity": finding.get("severity", "Unknown"),
                "severity_counts": {},
                "finding_count": 0,
                "vulnerability_count": 0,
                "affected_image_count": 0,
                "fix_available": False,
                "fixed_versions": [],
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

        cve = _cve_key(finding)
        if cve:
            item["_vulnerability_keys"].add(cve)

        image_key = _image_key(finding)
        if image_key and image_key not in item["_image_keys"]:
            item["_image_keys"].add(image_key)
            item["affected_images"].append(_image_ref(finding))

    result = []
    for item in grouped.values():
        package_findings = item.pop("_findings")
        item["severity_counts"] = _severity_counts(package_findings)
        item["vulnerability_count"] = len(item["_vulnerability_keys"])
        item["affected_image_count"] = len(item["_image_keys"])
        item["vulnerabilities"] = _build_vulnerability_groups_for_package(package_findings)
        item["affected_images"] = _sort_images(item["affected_images"])
        item["fixed_versions"] = sorted(item["fixed_versions"])
        item.pop("_vulnerability_keys", None)
        item.pop("_image_keys", None)
        result.append(item)

    return sorted(
        result,
        key=lambda item: (
            -_severity_rank(item["severity"]),
            -item["affected_image_count"],
            item["package_name"],
            item["package_version"],
            item["package_type"],
        ),
    )
