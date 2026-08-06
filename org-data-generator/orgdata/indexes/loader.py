"""Partition-aware input loaders for index generation.
Loads small entity files into dictionaries and iterates over partitioned
artifact-package, finding, package, and vulnerability files. Keeps index builder
logic independent from raw file layout details.
"""

from pathlib import Path

from orgdata.runtime.io import read_json


def load_json_records(path: Path):
    """Load either a raw list or an enveloped file with `records`."""
    if not path.is_file():
        return []
    data = read_json(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        records = data.get("records", [])
        if isinstance(records, list):
            return records
        if isinstance(records, dict):
            return list(records.values())
    return []


def load_json_object(path: Path, default=None):
    if not path.is_file():
        return default if default is not None else {}
    data = read_json(path)
    return data if isinstance(data, dict) else (default if default is not None else {})


def load_artifacts(current_dir: Path):
    return {
        item.get("artifact_id"): item
        for item in load_json_records(current_dir / "entities" / "artifacts.json")
        if item.get("artifact_id")
    }


def load_projects(current_dir: Path):
    return {
        item.get("project_id"): item
        for item in load_json_records(current_dir / "entities" / "projects.json")
        if item.get("project_id")
    }


def load_project_artifacts(current_dir: Path):
    result = {}
    for item in load_json_records(current_dir / "relationships" / "project-artifacts.json"):
        artifact_id = item.get("artifact_id")
        project_id = item.get("project_id")
        if artifact_id and project_id:
            result.setdefault(artifact_id, set()).add(project_id)
    return result


def artifact_package_files(current_dir: Path):
    path = current_dir / "relationships" / "artifact-packages" / "by-artifact"
    return sorted(path.glob("*.json")) if path.exists() else []


def finding_files(current_dir: Path):
    path = current_dir / "relationships" / "findings" / "by-artifact"
    return sorted(path.glob("*.json")) if path.exists() else []


def package_partition_files(current_dir: Path):
    path = current_dir / "entities" / "packages" / "by-type"
    return sorted(path.glob("*.json")) if path.exists() else []


def vulnerability_partition_files(current_dir: Path):
    path = current_dir / "entities" / "vulnerabilities" / "by-year"
    return sorted(path.glob("*.json")) if path.exists() else []


def load_artifact_packages(path: Path):
    data = load_json_object(path, {})
    return data.get("artifact_id", ""), data.get("packages", []) or []


def flatten_findings_document(data):
    findings = []
    grouped = data.get("findings", {}) if isinstance(data, dict) else {}
    for fixability_group in grouped.values():
        if not isinstance(fixability_group, dict):
            continue
        for severity_items in fixability_group.values():
            if isinstance(severity_items, list):
                findings.extend(severity_items)
    return findings


def load_findings(path: Path):
    data = load_json_object(path, {})
    return data.get("artifact_id", ""), flatten_findings_document(data)