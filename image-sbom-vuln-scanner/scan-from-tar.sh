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

if [ ! -w "$RESULT_DIR" ]; then
  echo "ERROR: result directory is not writable: $RESULT_DIR"
  exit 1
fi

SBOM_FILE="$RESULT_DIR/sbom-cyclonedx.json"
GRYPE_IMAGE_FILE="$RESULT_DIR/grype-image-vulns.json"
GRYPE_SBOM_FILE="$RESULT_DIR/grype-sbom-vulns.json"
GRYPE_IMAGE_TABLE_FILE="$RESULT_DIR/grype-image-vulns.table.txt"
GRYPE_SBOM_TABLE_FILE="$RESULT_DIR/grype-sbom-vulns.table.txt"
VERSIONS_FILE="$RESULT_DIR/scanner-tool-versions.txt"
SCAN_LOG="$RESULT_DIR/scanner-scan.log"

pretty_json() {
  local file="$1"
  jq . "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

vuln_summary() {
  local file="$1"
  jq -r '
    def count_sev($s): [.matches[]? | select((.vulnerability.severity // "Unknown" | ascii_downcase) == $s)] | length;
    "Critical=\(count_sev("critical")) High=\(count_sev("high")) Medium=\(count_sev("medium")) Low=\(count_sev("low")) Negligible=\(count_sev("negligible")) Unknown=\(count_sev("unknown"))"
  ' "$file"
}

{
  echo "Scanner started at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "Input tar: $IMAGE_TAR"
  echo "Result dir: $RESULT_DIR"
  echo "Running as UID:GID $(id -u):$(id -g)"
  echo "XDG_CACHE_HOME=${XDG_CACHE_HOME:-}"
  echo "GRYPE_DB_CACHE_DIR=${GRYPE_DB_CACHE_DIR:-}"
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

  echo "Formatting SBOM JSON..."
  pretty_json "$SBOM_FILE"

  echo "Running Grype scan against image tar..."
  grype "docker-archive:$IMAGE_TAR" \
    -o "json=$GRYPE_IMAGE_FILE" \
    -o "table=$GRYPE_IMAGE_TABLE_FILE"

  echo "Formatting Grype image JSON..."
  pretty_json "$GRYPE_IMAGE_FILE"

  echo "Running Grype scan against SBOM..."
  grype "sbom:$SBOM_FILE" \
    -o "json=$GRYPE_SBOM_FILE" \
    -o "table=$GRYPE_SBOM_TABLE_FILE"

  echo "Formatting Grype SBOM JSON..."
  pretty_json "$GRYPE_SBOM_FILE"

  echo "Validating JSON outputs..."
  jq empty "$SBOM_FILE"
  jq empty "$GRYPE_IMAGE_FILE"
  jq empty "$GRYPE_SBOM_FILE"

  echo
  echo "Scan summary:"
  echo "SBOM package count: $(jq '.components | length' "$SBOM_FILE")"
  echo "Image scan vulnerabilities: $(vuln_summary "$GRYPE_IMAGE_FILE")"
  echo "SBOM scan vulnerabilities:  $(vuln_summary "$GRYPE_SBOM_FILE")"

  chmod -R 777 "$RESULT_DIR" || true

  echo
  echo "Scanner completed at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
} 2>&1 | tee "$SCAN_LOG"
