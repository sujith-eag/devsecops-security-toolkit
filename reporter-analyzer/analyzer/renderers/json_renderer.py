"""JSON output renderer."""

import json
from pathlib import Path
from typing import Any

from analyzer.core.constants import DEFAULT_OUTPUT_FILENAME


def write_json_report(data: dict[str, Any], output_dir: str | Path, filename: str = DEFAULT_OUTPUT_FILENAME) -> Path:
    """Write report data as pretty, deterministic JSON."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    report_path = output_path / filename

    with report_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=False)
        handle.write("\n")

    return report_path