def _compact_dependencies(package_usage):
    return sorted(
        [
            {
                "name": item.get("package_name", ""),
                "type": item.get("package_type", ""),
                "versions": [
                    version.get("package_version", "")
                    for version in item.get("used_versions", [])
                ],
                "image_count": item.get("total_image_count", 0),
            }
            for item in package_usage
        ],
        key=lambda item: (
            item.get("type", ""),
            item.get("name", ""),
        ),
    )

def _compact_images(image_packages):
    return [
        {
            "image": item.get("image_reference", ""),
            "digest": item.get("image_digest", ""),
            "folder": item.get("image_folder", ""),
            "package_count": item.get("package_count", 0),
            "package_types": item.get("package_type_counts", {}),
        }
        for item in image_packages
    ]


def build_overview(run_metadata, all_packages, package_usage, image_packages, run_errors):
    package_type_counts = {}
    unique_package_versions = set()

    for record in all_packages:
        package_type = record.get("package_type") or "unknown"
        package_type_counts[package_type] = package_type_counts.get(package_type, 0) + 1
        unique_package_versions.add(record.get("package_version_key", ""))

    return {
        "run_summary": {
            "run_id": run_metadata.get("run_id"),
            "started_at": run_metadata.get("started_at"),
            "finished_at": run_metadata.get("finished_at"),
            "results_dir": run_metadata.get("results_dir"),
            "inventory_dir": run_metadata.get("inventory_dir"),
            "processed_count": run_metadata.get("processed_count", 0),
            "skipped_count": run_metadata.get("skipped_count", 0),
            "failed_count": run_metadata.get("failed_count", 0),
        },
        "counts": {
            "image_count": len(image_packages),
            "package_usage_count": len(all_packages),
            "unique_package_count": len(package_usage),
            "unique_package_version_count": len([x for x in unique_package_versions if x]),
            "error_count": len(run_errors),
        },
        "package_type_counts": dict(sorted(package_type_counts.items())),
        "dependencies": _compact_dependencies(package_usage),
        "images": _compact_images(image_packages),
        "run_errors": run_errors,
    }
