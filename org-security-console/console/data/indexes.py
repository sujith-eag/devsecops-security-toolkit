"""Low-level loaders for generated org-data indexes."""

import json
from pathlib import Path


def read_json(path: Path, default=None):
    if not path.is_file():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_json_files(path: Path):
    if not path.exists():
        return []
    data = []
    for file in sorted(path.glob("*.json")):
        value = read_json(file, [])
        if isinstance(value, list):
            data.extend(value)
        elif value is not None:
            data.append(value)
    return data


def load_by_artifact(index_dir: Path):
    path = index_dir / "by-artifact"
    result = {}
    if not path.exists():
        return result
    for file in sorted(path.glob("*.json")):
        item = read_json(file, {})
        artifact_id = (item.get("artifact") or {}).get("artifact_id")
        if artifact_id:
            result[artifact_id] = item
    return result


def load_by_package(index_dir: Path):
    return load_json_files(index_dir / "by-package" / "by-type")


def load_by_vulnerability(index_dir: Path):
    return load_json_files(index_dir / "by-vulnerability" / "by-year")


def load_remediation(index_dir: Path):
    return read_json(index_dir / "remediation.json", []) or []
