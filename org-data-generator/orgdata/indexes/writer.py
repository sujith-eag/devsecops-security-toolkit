"""Writers for production index files and manifests."""

import shutil
from datetime import datetime, timezone
from pathlib import Path

from orgdata.runtime.io import write_json
from orgdata.runtime.partitions import safe_filename

SCHEMA_VERSION = "1.0"
INDEX_VERSION = "2.0"


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def reset_indexes(current_dir: Path):
    index_dir = current_dir / "indexes"
    if index_dir.exists():
        shutil.rmtree(index_dir)
    index_dir.mkdir(parents=True, exist_ok=True)
    return index_dir


def envelope(index_type, records, partition=None, extra=None):
    payload = {
        "schema_version": SCHEMA_VERSION,
        "index_version": INDEX_VERSION,
        "index_type": index_type,
        "partition": partition,
        "generated_at": utc_now(),
        "record_count": len(records) if hasattr(records, "__len__") else 0,
        "records": records,
    }
    if extra:
        payload.update(extra)
    return payload


def write_index(path: Path, index_type, records, partition=None, extra=None):
    write_json(path, envelope(index_type, records, partition, extra))


def write_artifact_index(current_dir: Path, artifact_id: str, record):
    write_index(
        current_dir / "indexes" / "by-artifact" / f"{safe_filename(artifact_id)}.json",
        "by-artifact",
        [record],
        artifact_id,
    )


def write_package_index_partition(current_dir: Path, package_type: str, records):
    write_index(
        current_dir / "indexes" / "by-package" / "by-type" / f"{safe_filename(package_type)}.json",
        "by-package",
        records,
        package_type,
    )


def write_vulnerability_index_partition(current_dir: Path, bucket: str, records):
    write_index(
        current_dir / "indexes" / "by-vulnerability" / "by-year" / f"{safe_filename(bucket)}.json",
        "by-vulnerability",
        records,
        bucket,
    )


def write_remediation_index(current_dir: Path, records):
    write_index(current_dir / "indexes" / "remediation.json", "remediation", records)


def write_manifest(current_dir: Path, name: str, mapping):
    write_index(current_dir / "indexes" / "manifests" / f"{name}.json", f"manifest-{name}", mapping)


def write_index_metadata(current_dir: Path, metadata):
    write_json(current_dir / "indexes" / "index-metadata.json", metadata)


def write_index_summary(current_dir: Path, summary):
    write_json(current_dir / "indexes" / "index-summary.json", summary)


def write_index_validation(current_dir: Path, validation):
    write_json(current_dir / "indexes" / "index-validation.json", validation)