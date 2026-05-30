from pathlib import Path

REQUIRED_FILES = ("metadata.json", "sbom-cyclonedx.json")


def discover_result_folders(results_dir: Path):
    folders = []
    skipped = []

    for child in sorted(results_dir.iterdir()):
        if not child.is_dir():
            continue

        missing = [name for name in REQUIRED_FILES if not (child / name).is_file()]
        if missing:
            skipped.append({
                "image_folder": child.name,
                "stage": "discovery",
                "error_type": "missing_required_files",
                "message": f"Missing required file(s): {', '.join(missing)}",
                "missing_files": missing,
            })
            continue

        folders.append(child)

    return folders, skipped
