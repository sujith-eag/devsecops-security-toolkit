"""Load raw scan data from a result directory."""

from pathlib import Path

from analyzer.core.constants import (
    GRYPE_IMAGE_VULNS_FILE,
    GRYPE_SBOM_VULNS_FILE,
    METADATA_FILE,
    PRIMARY_VULNERABILITY_FILES,
    SBOM_FILE,
)
from analyzer.core.exceptions import InputValidationError
from analyzer.core.models import RawScanData, VulnerabilitySource
from analyzer.loaders.file_discovery import discover_files
from analyzer.loaders.json_loader import load_json


def _select_vulnerability_source(discovered: dict[str, Path]) -> VulnerabilitySource:
    """Select one primary vulnerability file.

    The standard source is grype-sbom-vulns.json. If it is unavailable, the
    image scan result is used as a fallback for image-based scans.
    """
    available_files = sorted(discovered.keys())

    for index, (filename, source_type) in enumerate(PRIMARY_VULNERABILITY_FILES):
        if filename in discovered:
            return VulnerabilitySource(
                primary_file=filename,
                primary_type=source_type,
                fallback_used=index > 0,
                available_files=available_files,
            )

    raise InputValidationError(
        f"No supported vulnerability file found. Expected {GRYPE_SBOM_VULNS_FILE} "
        f"or {GRYPE_IMAGE_VULNS_FILE}."
    )


def load_raw_scan(input_dir: str | Path) -> RawScanData:
    """Load metadata, optional SBOM, and the selected Grype vulnerability file."""
    scan_dir = Path(input_dir)
    discovered = discover_files(scan_dir)
    warnings: list[str] = []

    metadata_raw, metadata_warnings = load_json(scan_dir / METADATA_FILE, required=True)
    warnings.extend(metadata_warnings)
    if not isinstance(metadata_raw, dict):
        raise InputValidationError(f"{METADATA_FILE} must be a JSON object")

    sbom = None
    if SBOM_FILE in discovered:
        sbom_raw, sbom_warnings = load_json(scan_dir / SBOM_FILE, required=False)
        warnings.extend(sbom_warnings)
        if isinstance(sbom_raw, dict):
            sbom = sbom_raw
        elif sbom_raw is not None:
            warnings.append(f"Ignoring {SBOM_FILE}: expected a JSON object")
    else:
        warnings.append(f"Optional SBOM file missing: {SBOM_FILE}")

    vulnerability_source = _select_vulnerability_source(discovered)
    grype_raw, grype_warnings = load_json(scan_dir / vulnerability_source.primary_file, required=True)
    warnings.extend(grype_warnings)
    if not isinstance(grype_raw, dict):
        raise InputValidationError(f"{vulnerability_source.primary_file} must be a JSON object")

    if vulnerability_source.fallback_used:
        warnings.append(
            f"Primary SBOM vulnerability file missing; used fallback {vulnerability_source.primary_file}"
        )

    return RawScanData(
        input_dir=scan_dir,
        metadata=metadata_raw,
        sbom=sbom,
        grype=grype_raw,
        vulnerability_source=vulnerability_source,
        warnings=warnings,
    )
