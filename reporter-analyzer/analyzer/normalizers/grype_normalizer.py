"""Normalize Grype matches into a report-friendly finding model."""

import hashlib
from typing import Any

from analyzer.normalizers.package_identity import normalize_purl, normalized_package_type
from analyzer.normalizers.severity import normalize_severity


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first_location(artifact: dict[str, Any]) -> str:
    locations = _as_list(artifact.get("locations"))
    if not locations:
        return ""
    first = locations[0] or {}
    return first.get("accessPath") or first.get("path") or first.get("realPath") or ""


def _fixed_versions(vulnerability: dict[str, Any]) -> list[str]:
    fix = vulnerability.get("fix") or {}
    return [str(version) for version in _as_list(fix.get("versions")) if version]


def _cvss_score(vulnerability: dict[str, Any]) -> float | None:
    scores = []
    for item in _as_list(vulnerability.get("cvss")):
        metrics = (item or {}).get("metrics") or {}
        score = metrics.get("baseScore")
        if isinstance(score, (int, float)):
            scores.append(float(score))
    return max(scores) if scores else None


def _epss_score(vulnerability: dict[str, Any]) -> float | None:
    scores = []
    for item in _as_list(vulnerability.get("epss")):
        score = (item or {}).get("epss")
        if isinstance(score, (int, float)):
            scores.append(float(score))
    return max(scores) if scores else None


def _cwes(vulnerability: dict[str, Any]) -> list[str]:
    values = []
    for item in _as_list(vulnerability.get("cwes")):
        if isinstance(item, dict):
            value = item.get("cwe") or item.get("id")
        else:
            value = item
        if value:
            values.append(str(value))
    return sorted(set(values))


def _urls(vulnerability: dict[str, Any]) -> list[str]:
    values = []
    for item in _as_list(vulnerability.get("urls")):
        if item:
            values.append(str(item))
    data_source = vulnerability.get("dataSource")
    if data_source:
        values.append(str(data_source))
    return sorted(set(values))


def _match_type(match: dict[str, Any]) -> str:
    match_details = _as_list(match.get("matchDetails"))
    if not match_details:
        return ""
    return str((match_details[0] or {}).get("type") or "")


def _finding_id(vulnerability_id: str, package_name: str, package_version: str, package_type: str, location: str) -> str:
    raw = "|".join([vulnerability_id, package_name, package_version, package_type, location])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def normalize_grype_matches(grype_data: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    """Convert Grype `matches` into stable normalized findings.

    Vulnerability findings are never dropped only because the scanner reports a
    noisy package type such as `file`. Instead, package type is derived from PURL
    first and then normalized from the scanner value.
    """
    findings: list[dict[str, Any]] = []

    for match in _as_list(grype_data.get("matches")):
        if not isinstance(match, dict):
            continue

        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}

        vulnerability_id = str(vulnerability.get("id") or "")
        package_name = str(artifact.get("name") or "")
        package_version = str(artifact.get("version") or "")
        package_purl = normalize_purl(artifact.get("purl") or "")
        package_type = normalized_package_type(raw_type=artifact.get("type"), purl=package_purl)
        location = _first_location(artifact)
        fixed_versions = _fixed_versions(vulnerability)

        findings.append(
            {
                "finding_id": _finding_id(
                    vulnerability_id,
                    package_name,
                    package_version,
                    package_type,
                    location,
                ),
                "vulnerability_id": vulnerability_id,
                "severity": normalize_severity(vulnerability.get("severity")),
                "package": {
                    "name": package_name,
                    "version": package_version,
                    "type": package_type,
                    "purl": package_purl,
                },
                "fix": {
                    "fix_available": bool(fixed_versions),
                    "fixed_versions": fixed_versions,
                },
                "risk": {
                    "cvss_score": _cvss_score(vulnerability),
                    "epss_score": _epss_score(vulnerability),
                    "cwes": _cwes(vulnerability),
                },
                "details": {
                    "namespace": str(vulnerability.get("namespace") or ""),
                    "description": str(vulnerability.get("description") or ""),
                    "urls": _urls(vulnerability),
                    "location": location,
                },
                "source": {
                    "file": source_file,
                    "match_type": _match_type(match),
                },
            }
        )

    return findings