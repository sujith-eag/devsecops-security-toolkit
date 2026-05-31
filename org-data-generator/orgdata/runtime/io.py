"""
Shared JSON and filesystem helpers.

Provides UTF-8 JSON read/write helpers and directory reset behavior for the
current org-data output directory. JSON output uses `ensure_ascii=False` so
Unicode characters remain readable.
"""

import json
import shutil
from pathlib import Path


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def reset_dir(path: Path):
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
