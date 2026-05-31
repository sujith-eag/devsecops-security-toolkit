from orgdata.inventory.metadata import parse_metadata
from orgdata.inventory.sbom import merge_artifact_package, merge_package, normalize_component, parse_components


def build_inventory_records(artifact_folder, metadata, sbom_data):
    artifact, project, project_artifact = parse_metadata(metadata, artifact_folder)
    packages = {}
    artifact_packages = {}
    warnings = []

    for component in parse_components(sbom_data):
        package, relationship = normalize_component(component, artifact["artifact_id"])
        if not package:
            continue

        package_id = package["package_id"]
        if package_id in packages:
            packages[package_id] = merge_package(packages[package_id], package)
        else:
            packages[package_id] = package

        rel_key = "|".join([relationship["artifact_id"], relationship["package_id"]])
        if rel_key in artifact_packages:
            artifact_packages[rel_key] = merge_artifact_package(artifact_packages[rel_key], relationship)
        else:
            artifact_packages[rel_key] = relationship

    if not artifact.get("project_id"):
        warnings.append({
            "artifact_id": artifact["artifact_id"],
            "stage": "inventory",
            "warning_type": "artifact_without_project",
            "message": "Artifact has no project_id and will be included as artifact-only data.",
        })

    return {
        "artifact": artifact,
        "project": project,
        "project_artifact": project_artifact,
        "packages": list(packages.values()),
        "artifact_packages": list(artifact_packages.values()),
        "warnings": warnings,
    }
