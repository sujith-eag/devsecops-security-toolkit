"""Safe JSON loading helpers."""

import json
from pathlib import Path
from typing import Any

from analyzer.core.exceptions import InputValidationError


def load_json(path: Path, *, required: bool = True) -> tuple[dict[str, Any] | list[Any] | None, list[str]]:
    """Load JSON from disk.

    Required files raise InputValidationError when missing or malformed.
    Optional files return None and a warning when missing or malformed.
    """
    if not path.is_file():
        if required:
            raise InputValidationError(f"Required JSON file missing: {path}")
        return None, [f"Optional JSON file missing: {path.name}"]

    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle), []
    except json.JSONDecodeError as exc:
        message = f"Malformed JSON in {path.name}: {exc}"
        if required:
            raise InputValidationError(message) from exc
        return None, [message]
