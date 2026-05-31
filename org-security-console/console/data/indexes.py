"""Low-level loaders for production org-data indexes.

Production indexes are enveloped JSON files with a `records` field. This module
also remains backward-compatible with older raw-list index files.
"""

import json
from pathlib import Path


def read_json(path: Path, default=None):
    if not path.is_file():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def records_from_payload(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        records = payload.get("records", [])
        if isinstance(records, list):
            return records
        if isinstance(records, dict):
            return list(records.values())
    return []


def load_records(path: Path):
    return records_from_payload(read_json(path, []))


def load_mapping(path: Path):
    payload = read_json(path, {}) or {}
    if isinstance(payload, dict) and isinstance(payload.get("records"), dict):
        return payload["records"]
    if isinstance(payload, dict):
        return payload
    return {}


def load_json_files(path: Path):
    if not path.exists():
        return []
    data = []
    for file in sorted(path.glob("*.json")):
        data.extend(load_records(file))
    return data


def load_by_artifact(index_dir: Path):
    result = {}
    path = index_dir / "by-artifact"
    if not path.exists():
        return result
    for file in sorted(path.glob("*.json")):
        records = load_records(file)
        if records:
            item = records[0]
            artifact_id = item.get("artifact_id") or (item.get("artifact") or {}).get("artifact_id") or item.get("canonical_id")
            if artifact_id:
                result[artifact_id] = item
    return result


def load_by_package(index_dir: Path):
    return load_json_files(index_dir / "by-package" / "by-type")


def load_by_vulnerability(index_dir: Path):
    return load_json_files(index_dir / "by-vulnerability" / "by-year")


def load_remediation(index_dir: Path):
    return load_records(index_dir / "remediation.json")


def load_manifests(index_dir: Path):
    manifest_dir = index_dir / "manifests"
    return {
        "artifacts": load_mapping(manifest_dir / "artifacts.json"),
        "packages": load_mapping(manifest_dir / "packages.json"),
        "vulnerabilities": load_mapping(manifest_dir / "vulnerabilities.json"),
        "remediation": load_mapping(manifest_dir / "remediation.json"),
        "partitions": load_mapping(manifest_dir / "partitions.json"),
    }