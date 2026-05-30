import json
from pathlib import Path


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def first_present(data, keys, default=""):
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return default


def image_info(metadata: dict, image_folder: str):
    image_ref = first_present(metadata, ["image_reference", "image", "image_ref", "reference", "original_image"], "")
    image_name = first_present(metadata, ["image_name", "name", "repository", "repo"], "")
    image_tag = first_present(metadata, ["image_tag", "tag"], "")
    image_digest = first_present(metadata, ["image_digest", "digest", "repo_digest", "id", "image_id"], "")

    if not image_name and image_ref:
        image_name = image_ref.split("@")[0].split(":")[0]
    if not image_tag and image_ref and ":" in image_ref and "@" not in image_ref:
        image_tag = image_ref.rsplit(":", 1)[-1]

    return {
        "image_folder": image_folder,
        "image_reference": image_ref,
        "image_name": image_name,
        "image_tag": image_tag,
        "image_digest": image_digest or image_folder,
    }


def normalize_fixed_versions(fix_data):
    if not isinstance(fix_data, dict):
        return []
    versions = fix_data.get("versions") or []
    return sorted(str(v) for v in versions if v is not None)


def normalize_grype_data(grype_data: dict, metadata: dict, image_folder: str, source_file="grype-sbom-vulns.json"):
    info = image_info(metadata, image_folder)
    findings = []

    for match in grype_data.get("matches", []) or []:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        fix_data = vulnerability.get("fix") or {}
        match_details = match.get("matchDetails") or []

        vulnerability_id = str(vulnerability.get("id") or "")
        package_name = str(artifact.get("name") or "")
        package_version = str(artifact.get("version") or "")
        package_type = str(artifact.get("type") or "")
        severity = str(vulnerability.get("severity") or "Unknown")
        fix_state = str(fix_data.get("state") or "unknown")
        fixed_versions = normalize_fixed_versions(fix_data)
        grype_match_type = ""
        if match_details and isinstance(match_details[0], dict):
            grype_match_type = str(match_details[0].get("type") or "")

        finding_key = "|".join([
            info["image_digest"],
            vulnerability_id,
            package_name,
            package_version,
            package_type,
        ])

        findings.append({
            "finding_key": finding_key,
            **info,
            "vulnerability_id": vulnerability_id,
            "severity": severity,
            "package_name": package_name,
            "package_version": package_version,
            "package_type": package_type,
            "fix_state": fix_state,
            "fixed_versions": fixed_versions,
            "grype_match_type": grype_match_type,
            "source_file": source_file,
        })

    return findings


SEVERITY_RANK = {
    "Unknown": 0,
    "Negligible": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
}


def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def _merge_unique(existing, new_values):
    merged = list(existing or [])
    for value in _as_list(new_values):
        if value not in (None, "") and value not in merged:
            merged.append(value)
    return merged


def _higher_severity(current, new):
    current_rank = SEVERITY_RANK.get(current or "Unknown", 0)
    new_rank = SEVERITY_RANK.get(new or "Unknown", 0)
    return new if new_rank > current_rank else current


def deduplicate_findings(findings):
    deduped = {}

    for finding in findings:
        key = finding.get("finding_key", "")

        if key not in deduped:
            item = dict(finding)
            item["duplicate_count"] = 1
            item["grype_match_types"] = _as_list(finding.get("grype_match_type"))
            item["fixed_versions"] = _merge_unique([], finding.get("fixed_versions"))
            deduped[key] = item
            continue

        item = deduped[key]
        item["duplicate_count"] = item.get("duplicate_count", 1) + 1
        item["fixed_versions"] = _merge_unique(item.get("fixed_versions"), finding.get("fixed_versions"))
        item["grype_match_types"] = _merge_unique(item.get("grype_match_types"), finding.get("grype_match_type"))

        item["severity"] = _higher_severity(item.get("severity"), finding.get("severity"))

        if item.get("fix_state") != "fixed" and finding.get("fix_state") == "fixed":
            item["fix_state"] = "fixed"

        if not item.get("grype_match_type") and finding.get("grype_match_type"):
            item["grype_match_type"] = finding.get("grype_match_type")

    return sorted(deduped.values(), key=lambda item: item.get("finding_key", ""))
