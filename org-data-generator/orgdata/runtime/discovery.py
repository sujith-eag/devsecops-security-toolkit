"""
Discovers valid scan result folders under the runtime results directory.

A valid folder must contain at least `metadata.json` and `sbom-cyclonedx.json`.
Invalid or incomplete folders are not fatal; they are returned as structured
errors so the main process can continue with other artifacts.
"""

from pathlib import Path

REQUIRED_FILES = ("metadata.json", "sbom-cyclonedx.json")


def discover_result_folders(results_dir: Path):
    folders = []
    errors = []

    for child in sorted(results_dir.iterdir()):
        if not child.is_dir():
            continue

        missing = [name for name in REQUIRED_FILES if not (child / name).is_file()]
        if missing:
            errors.append({
                "artifact_folder": child.name,
                "stage": "discovery",
                "error_type": "missing_required_files",
                "message": f"Missing required file(s): {', '.join(missing)}",
                "missing_files": missing,
            })
            continue

        folders.append(child)

    return folders, errors
