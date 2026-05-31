import json
import re
from pathlib import Path

from orgdata.runtime.io import write_json


def safe_filename(value):
    text = str(value or "unknown")
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text)
    return text.strip("_") or "unknown"


def append_jsonl(path: Path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def append_many_jsonl(path: Path, records):
    if not records:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_jsonl(path: Path):
    if not path.is_file():
        return []
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def finalize_partition_dir(tmp_dir: Path, output_dir: Path, id_field: str, merge_func):
    output_dir.mkdir(parents=True, exist_ok=True)
    produced_files = []
    id_set = set()

    if not tmp_dir.exists():
        return produced_files, id_set

    for jsonl_file in sorted(tmp_dir.glob("*.jsonl")):
        merged = {}
        for record in read_jsonl(jsonl_file):
            key = record.get(id_field)
            if not key:
                continue
            if key in merged:
                merged[key] = merge_func(merged[key], record)
            else:
                merged[key] = record

        final_records = sorted(merged.values(), key=lambda item: item.get(id_field, ""))
        final_path = output_dir / f"{jsonl_file.stem}.json"
        write_json(final_path, final_records)
        produced_files.append(str(final_path))
        id_set.update(merged.keys())

    return produced_files, id_set
