import json
import os
import sys


def load_json(path, required=True):
    if not os.path.isfile(path):
        if required:
            print(f"ERROR: required file missing: {path}")
            sys.exit(1)
        return None

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_inputs(input_dir):
    warnings = []

    metadata = load_json(os.path.join(input_dir, "metadata.json"), required=True)
    artifact_type = metadata.get("artifact_type", "")

    if artifact_type == "container_image":
        vuln_file = "grype-image-vulns.json"
    elif artifact_type == "source_project":
        vuln_file = "grype-sbom-vulns.json"
    else:
        vuln_file = "grype-sbom-vulns.json"
        warnings.append(f"Unknown artifact_type '{artifact_type}', using grype-sbom-vulns.json as vulnerability source")

    grype_data = load_json(os.path.join(input_dir, vuln_file), required=True)

    sbom_path = os.path.join(input_dir, "sbom-cyclonedx.json")
    sbom = load_json(sbom_path, required=False)

    if sbom is None:
        warnings.append("Optional SBOM file missing: sbom-cyclonedx.json")

    warnings.append(f"Vulnerability source used: {vuln_file}")

    return metadata, grype_data, sbom, warnings
