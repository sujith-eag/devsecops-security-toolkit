#!/usr/bin/env bash
# entrypoint.sh — Orchestrator for the merged devsecops-scanner image.
# Usage:
#   /entrypoint.sh image <image-ref>     # scan a container image from registry
#   /entrypoint.sh dir   <source-path>   # scan a source directory
set -euo pipefail

TOOLKIT_DIR="/toolkit"
SCANNER_DIR="${TOOLKIT_DIR}/image-sbom-vuln-scanner"
REPORTER_DIR="${TOOLKIT_DIR}/reporter-analyzer"

SCAN_OUTPUT_DIR="${SCAN_OUTPUT_DIR:-/output}"
SCRATCH_SCAN="/tmp/scan-results"
SCRATCH_ANALYSIS="/tmp/analysis"

PROJECT_NAME="${PROJECT_NAME:-unknown-project}"
PROJECT_BRANCH="${PROJECT_BRANCH:-unknown-branch}"
PROJECT_COMMIT="${PROJECT_COMMIT:-unknown-commit}"
ARTIFACT_ROLE="${ARTIFACT_ROLE:-service}"

log() { echo "[entrypoint] $*"; }
die() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

if [ $# -lt 2 ]; then
    echo "Usage: entrypoint.sh <image|dir> <image-ref|source-path>"
    exit 1
fi

MODE="$1"
TARGET="$2"

[ "$MODE" = "image" ] || [ "$MODE" = "dir" ] || die "Mode must be 'image' or 'dir', got: $MODE"

log "Creating scratch directories..."
mkdir -p "${SCRATCH_SCAN}" "${SCRATCH_ANALYSIS}" "${SCAN_OUTPUT_DIR}"

log "Writing metadata.json..."
cat > "${SCRATCH_SCAN}/metadata.json" <<EOF
{
  "project_name": "${PROJECT_NAME}",
  "branch": "${PROJECT_BRANCH}",
  "commit": "${PROJECT_COMMIT}",
  "artifact_role": "${ARTIFACT_ROLE}",
  "scan_mode": "${MODE}",
  "scan_target": "${TARGET}"
}
