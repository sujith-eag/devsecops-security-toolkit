from orgdata.inventory.metadata import parse_metadata
from orgdata.inventory.sbom import merge_artifact_package, normalize_component, parse_components


def build_inventory_records(artifact_folder, metadata, sbom_data):
    artifact, project, project_artifact = parse_metadata(metadata, artifact_folder)
    packages = []
    artifact_packages = {}
    warnings = []

    for component in parse_components(sbom_data):
        package, relationship = normalize_component(component, artifact["artifact_id"])
        if not package:
            continue
        packages.append(package)
        rel_key = "|".join([relationship["artifact_id"], relationship["package_id"]])
        artifact_packages[rel_key] = merge_artifact_package(artifact_packages[rel_key], relationship) if rel_key in artifact_packages else relationship

    if not artifact.get("project_id"):
        warnings.append({
            "artifact_id": artifact["artifact_id"],
            "stage": "inventory",
            "warning_type": "artifact_without_project",
            "message": "Artifact has no project_id and is included as artifact-only data.",
        })

    return {
        "artifact": artifact,
        "project": project,
        "project_artifact": project_artifact,
        "packages": packages,
        "artifact_packages": sorted(artifact_packages.values(), key=lambda x: x.get("package_id", "")),
        "warnings": warnings,
    }
