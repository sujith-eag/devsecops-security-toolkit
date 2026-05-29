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
    grype_image = load_json(os.path.join(input_dir, "grype-image-vulns.json"), required=True)

    sbom_path = os.path.join(input_dir, "sbom-cyclonedx.json")
    sbom = load_json(sbom_path, required=False)

    if sbom is None:
        warnings.append("Optional SBOM file missing: sbom-cyclonedx.json")

    return metadata, grype_image, sbom, warnings
