"""Shared constants for the reporter analyzer."""

SCHEMA_VERSION = "reporter.initial.v1"
DEFAULT_OUTPUT_FILENAME = "initial-report-data.json"

METADATA_FILE = "metadata.json"
SBOM_FILE = "sbom-cyclonedx.json"
GRYPE_SBOM_VULNS_FILE = "grype-sbom-vulns.json"
GRYPE_IMAGE_VULNS_FILE = "grype-image-vulns.json"
SCANNER_TOOL_VERSIONS_FILE = "scanner-tool-versions.txt"
SCANNER_SCAN_LOG_FILE = "scanner-scan.log"
HOST_SCAN_LOG_FILE = "host-scan.log"

KNOWN_INPUT_FILES = [
    METADATA_FILE,
    SBOM_FILE,
    GRYPE_SBOM_VULNS_FILE,
    GRYPE_IMAGE_VULNS_FILE,
    SCANNER_TOOL_VERSIONS_FILE,
    SCANNER_SCAN_LOG_FILE,
    HOST_SCAN_LOG_FILE,
]

PRIMARY_VULNERABILITY_FILES = [
    (GRYPE_SBOM_VULNS_FILE, "sbom"),
    (GRYPE_IMAGE_VULNS_FILE, "image"),
]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"]
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
