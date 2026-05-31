"""
Index output writer helpers.

Resets the `indexes/` directory and writes by-artifact, by-package,
by-vulnerability, and remediation index outputs in their agreed partitioned
locations.
"""

import shutil
from pathlib import Path

from orgdata.runtime.io import write_json
from orgdata.runtime.partitions import safe_filename


def reset_indexes(current_dir: Path):
    index_dir = current_dir / "indexes"
    if index_dir.exists():
        shutil.rmtree(index_dir)
    index_dir.mkdir(parents=True, exist_ok=True)
    return index_dir


def write_artifact_index(current_dir: Path, artifact_id: str, data):
    write_json(current_dir / "indexes" / "by-artifact" / f"{safe_filename(artifact_id)}.json", data)


def write_package_index_partition(current_dir: Path, package_type: str, data):
    write_json(current_dir / "indexes" / "by-package" / "by-type" / f"{safe_filename(package_type)}.json", data)


def write_vulnerability_index_partition(current_dir: Path, bucket: str, data):
    write_json(current_dir / "indexes" / "by-vulnerability" / "by-year" / f"{safe_filename(bucket)}.json", data)


def write_remediation_index(current_dir: Path, data):
    write_json(current_dir / "indexes" / "remediation.json", data)
