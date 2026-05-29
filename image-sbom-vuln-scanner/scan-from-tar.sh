#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAR="${1:-}"
RESULT_DIR="${2:-}"

if [ -z "$IMAGE_TAR" ] || [ -z "$RESULT_DIR" ]; then
  echo "Usage: $0 <image-tar-path> <result-dir>"
  exit 1
fi

if [ ! -f "$IMAGE_TAR" ]; then
  echo "ERROR: image tar not found: $IMAGE_TAR"
  exit 1
fi

if [ ! -d "$RESULT_DIR" ]; then
  echo "ERROR: result directory not found: $RESULT_DIR"
  exit 1
fi

SBOM_FILE="$RESULT_DIR/sbom-cyclonedx.json"
GRYPE_IMAGE_FILE="$RESULT_DIR/grype-image-vulns.json"
GRYPE_SBOM_FILE="$RESULT_DIR/grype-sbom-vulns.json"
VERSIONS_FILE="$RESULT_DIR/scanner-tool-versions.txt"
SCAN_LOG="$RESULT_DIR/scanner-scan.log"

{
  echo "Scanner started at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "Input tar: $IMAGE_TAR"
  echo "Result dir: $RESULT_DIR"
  echo
  echo "Syft version:"
  syft version
  echo
  echo "Grype version:"
  grype version
} > "$VERSIONS_FILE"

{
  echo "Generating CycloneDX SBOM..."
  syft "docker-archive:$IMAGE_TAR" -o "cyclonedx-json=$SBOM_FILE"

  echo "Running Grype scan against image tar..."
  grype "docker-archive:$IMAGE_TAR" -o json --file "$GRYPE_IMAGE_FILE"

  echo "Running Grype scan against SBOM..."
  grype "sbom:$SBOM_FILE" -o json --file "$GRYPE_SBOM_FILE"

  echo "Validating JSON outputs..."
  jq empty "$SBOM_FILE"
  jq empty "$GRYPE_IMAGE_FILE"
  jq empty "$GRYPE_SBOM_FILE"

  echo "Scanner completed at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
} 2>&1 | tee "$SCAN_LOG"
