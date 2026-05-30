import argparse
import uuid
from datetime import datetime, timezone
from pathlib import Path

from inventory.packages.indexes import build_image_packages, build_package_usage
from inventory.packages.normalizer import deduplicate_package_usages, normalize_component
from inventory.reports.overview import build_overview
from inventory.runtime.discovery import discover_result_folders
from inventory.runtime.io import read_json, write_json
from inventory.sbom.parser import parse_cyclonedx_components


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def error_entry(image_folder, stage, error_type, message, **extra):
    return {
        "image_folder": image_folder,
        "stage": stage,
        "error_type": error_type,
        "message": message,
        **extra,
    }


def main():
    parser = argparse.ArgumentParser(description="Build package inventory from existing CycloneDX SBOM files.")
    parser.add_argument("results_dir", help="Path to runtime results directory, e.g. /results")
    parser.add_argument("--inventory-dir", default="/inventory", help="Path to inventory output directory")
    args = parser.parse_args()

    started_at = utc_now()
    run_id = str(uuid.uuid4())
    results_dir = Path(args.results_dir).resolve()
    inventory_dir = Path(args.inventory_dir).resolve()
    current_dir = inventory_dir / "current"
    run_errors = []
    package_records = []

    if not results_dir.is_dir():
        raise SystemExit(f"Results directory does not exist or is not a directory: {results_dir}")

    folders, skipped = discover_result_folders(results_dir)
    run_errors.extend(skipped)

    processed_count = 0
    failed_count = 0

    for folder in folders:
        image_folder = folder.name
        metadata_path = folder / "metadata.json"
        sbom_path = folder / "sbom-cyclonedx.json"

        try:
            metadata = read_json(metadata_path)
        except Exception as exc:
            failed_count += 1
            run_errors.append(error_entry(image_folder, "metadata_parse", "invalid_metadata_json", str(exc)))
            continue

        try:
            sbom_data = read_json(sbom_path)
            components = parse_cyclonedx_components(sbom_data)
        except Exception as exc:
            failed_count += 1
            run_errors.append(error_entry(image_folder, "sbom_parse", "invalid_sbom_json", str(exc)))
            continue

        for component in components:
            try:
                record = normalize_component(component, metadata, image_folder)

                if not record.get("package_name"):
                    continue

                # if record.get("component_type") == "file":
                #     continue
                if record.get("component_type") in ("file", "operating-system"):
                    continue

                package_records.append(record)
            except Exception as exc:
                run_errors.append(error_entry(image_folder, "component_normalize", "component_normalize_failed", str(exc)))

        processed_count += 1

    all_packages = deduplicate_package_usages(package_records)
    package_usage = build_package_usage(all_packages)
    image_packages = build_image_packages(all_packages)

    run_metadata = {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": utc_now(),
        "results_dir": str(results_dir),
        "inventory_dir": str(inventory_dir),
        "total_folders_discovered": len(folders) + len(skipped),
        "valid_sbom_folders": len(folders),
        "processed_count": processed_count,
        "skipped_count": len(skipped),
        "failed_count": failed_count,
        "package_usage_count": len(all_packages),
        "unique_package_count": len(package_usage),
        "image_count": len(image_packages),
        "error_count": len(run_errors),
    }

    overview = build_overview(run_metadata, all_packages, package_usage, image_packages, run_errors)

    write_json(current_dir / "packages" / "all-packages.json", all_packages)
    write_json(current_dir / "packages" / "package-usage.json", package_usage)
    write_json(current_dir / "packages" / "image-packages.json", image_packages)
    write_json(current_dir / "reports" / "overview.json", overview)
    write_json(current_dir / "run" / "run-errors.json", run_errors)
    write_json(current_dir / "run" / "run-metadata.json", run_metadata)

    print(
        f"SBOM inventory completed: processed={processed_count}, skipped={len(skipped)}, "
        f"failed={failed_count}, package_usages={len(all_packages)}, "
        f"unique_packages={len(package_usage)}, images={len(image_packages)}, errors={len(run_errors)}"
    )


if __name__ == "__main__":
    main()
