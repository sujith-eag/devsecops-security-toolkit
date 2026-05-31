"""Path helpers for org-data and report output locations."""

from pathlib import Path


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    return path
