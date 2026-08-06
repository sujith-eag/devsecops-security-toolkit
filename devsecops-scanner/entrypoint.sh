#!/usr/bin/env bash
# entrypoint.sh - Orchestrator for the merged devsecops-scanner image.
# Usage:
#   /entrypoint.sh image <image-ref>     # scan a container image from registry
#   /entrypoint.sh dir   <source-path>   # scan a source directory
#
# Environment variables:
#   SCAN_OUTPUT_DIR   Final output location (default: /output)
#   PROJECT_NAME      Project name for reports
#   PROJECT_BRANCH    Branch name for reports
#   PROJECT_COMMIT    Commit SHA for reports
#   ARTIFACT_ROLE     Artifact role tag (default: source)
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION  (ECR auth for image mode)
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
ARTIFACT_ROLE="${ARTIFACT_ROLE:-source}"

# Grype DB cache location - writable scratch space inside the container
export GRYPE_DB_CACHE_DIR="${GRYPE_DB_CACHE_DIR:-/tmp/grype-db}"

step() { echo "[$1] $2"; }
die() { echo "FAILED"; echo "      Error: $*" >&2; echo ""; echo "Scan failed at step ${CURRENT_STEP:-0}/4."; exit 1; }

# --- Argument parsing ---
if [ $# -lt 2 ]; then
    echo "Usage: entrypoint.sh <image|dir> <image-ref|source-path>"
    exit 1
fi

MODE="$1"
TARGET="$2"

[ "$MODE" = "image" ] || [ "$MODE" = "dir" ] || die "Mode must be 'image' or 'dir', got: $MODE"

# --- Setup ---
mkdir -p "${SCRATCH_SCAN}" "${SCRATCH_ANALYSIS}" "${SCAN_OUTPUT_DIR}"

# --- Scan header ---
echo ""
echo "========================================"
echo "SECURITY SCAN"
echo "========================================"
echo "Project:  ${PROJECT_NAME} (${PROJECT_BRANCH})"
echo "Commit:   ${PROJECT_COMMIT:0:7}"
# Show short target name (strip registry for image mode)
if [ "$MODE" = "image" ]; then
    SHORT_TARGET=$(echo "${TARGET}" | sed 's|.*/||')
else
    SHORT_TARGET="${TARGET}"
fi
echo "Target:   ${SHORT_TARGET}"
echo ""

# --- Write metadata.json using Python (nested schema for reporter-analyzer) ---

export _META_MODE="${MODE}"
export _META_TARGET="${TARGET}"
export _META_PROJECT_NAME="${PROJECT_NAME}"
export _META_PROJECT_BRANCH="${PROJECT_BRANCH}"
export _META_PROJECT_COMMIT="${PROJECT_COMMIT}"

python3 -c "
import json, os
from datetime import datetime, timezone

mode = os.environ['_META_MODE']
target = os.environ['_META_TARGET']
project_name = os.environ.get('_META_PROJECT_NAME', '')
project_branch = os.environ.get('_META_PROJECT_BRANCH', '')
project_commit = os.environ.get('_META_PROJECT_COMMIT', '')
timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

if mode == 'image':
    name_tag = target.rsplit('/', 1)[-1]
    name_parts = name_tag.split(':')
    image_name = name_parts[0]
    image_tag = name_parts[1] if len(name_parts) > 1 else 'latest'
    meta = {
        'artifact_id': name_tag,
        'artifact_type': 'container_image',
        'image': {
            'image_ref': target,
            'image_name': image_name,
            'image_tag': image_tag,
        },
        'project': {
            'project_name': project_name,
            'project_branch': project_branch,
            'project_commit': project_commit,
        },
        'scan': {
            'scan_type': 'image',
            'scan_timestamp_utc': timestamp,
        },
    }
else:
    meta = {
        'artifact_id': project_name,
        'artifact_type': 'source_project',
        'source': {
            'source_path': target,
            'source_branch': project_branch,
            'source_commit': project_commit,
        },
        'project': {
            'project_name': project_name,
            'project_branch': project_branch,
            'project_commit': project_commit,
        },
        'scan': {
            'scan_type': 'source',
            'scan_timestamp_utc': timestamp,
        },
    }

print(json.dumps(meta, indent=2))
" > "${SCRATCH_SCAN}/metadata.json"

CURRENT_STEP=1
step "1/4" "Updating vulnerability database..."
grype db update || die "Failed to update vulnerability database"

if [ "$MODE" = "image" ]; then
    IMAGE_REF="${TARGET}"

    if [ -n "${AWS_DEFAULT_REGION:-}" ]; then
        REGISTRY_HOST=$(echo "${IMAGE_REF}" | cut -d'/' -f1)
        ECR_PASSWORD=$(aws ecr get-login-password --region "${AWS_DEFAULT_REGION}" 2>/dev/null || true)
        if [ -n "${ECR_PASSWORD}" ]; then
            export SYFT_REGISTRY_AUTH_AUTHORITY="${REGISTRY_HOST}"
            export SYFT_REGISTRY_AUTH_USERNAME="AWS"
            export SYFT_REGISTRY_AUTH_PASSWORD="${ECR_PASSWORD}"
            export GRYPE_REGISTRY_AUTH_AUTHORITY="${REGISTRY_HOST}"
            export GRYPE_REGISTRY_AUTH_USERNAME="AWS"
            export GRYPE_REGISTRY_AUTH_PASSWORD="${ECR_PASSWORD}"
        fi
    fi

    CURRENT_STEP=2
    step "2/4" "Generating SBOM..."
    syft "registry:${IMAGE_REF}" \
        -o "cyclonedx-json=${SCRATCH_SCAN}/sbom-cyclonedx.json" \
        --scope all-layers || die "SBOM generation failed - check ECR auth and image availability"

    PKG_COUNT=$(jq '.components | length' "${SCRATCH_SCAN}/sbom-cyclonedx.json" 2>/dev/null || echo "0")
    echo "      Packages found: ${PKG_COUNT}"

    CURRENT_STEP=3
    step "3/4" "Scanning for vulnerabilities..."
    grype "sbom:${SCRATCH_SCAN}/sbom-cyclonedx.json" \
        -o "json=${SCRATCH_SCAN}/grype-sbom-vulns.json" || die "Vulnerability scan failed"

    VULN_SUMMARY=$(jq -r '
      def count_sev($s): [.matches[]? | select((.vulnerability.severity // "Unknown" | ascii_downcase) == $s)] | length;
      "Critical=\(count_sev("critical")) High=\(count_sev("high")) Medium=\(count_sev("medium")) Low=\(count_sev("low"))"
    ' "${SCRATCH_SCAN}/grype-sbom-vulns.json" 2>/dev/null || echo "Critical=0 High=0 Medium=0 Low=0")
    echo "      Vulnerabilities: ${VULN_SUMMARY}"

elif [ "$MODE" = "dir" ]; then
    [ -d "${TARGET}" ] || die "Source directory does not exist: ${TARGET}"

    CURRENT_STEP=2
    step "2/4" "Generating SBOM..."
    bash "${SCANNER_DIR}/scan-from-dir.sh" "${TARGET}" "${SCRATCH_SCAN}" 2>&1 | grep -E "SBOM package count|SBOM scan vulnerabilities" | sed 's/^/      /' || true

    CURRENT_STEP=3
    step "3/4" "Scanning for vulnerabilities..."
    # scan-from-dir.sh already runs grype, so just verify outputs
fi

[ -f "${SCRATCH_SCAN}/sbom-cyclonedx.json" ]  || die "SBOM file missing after scan"
[ -f "${SCRATCH_SCAN}/grype-sbom-vulns.json" ] || die "Vulnerability file missing after scan"
echo "      ok"

CURRENT_STEP=4
step "4/4" "Generating reports..."
cd "${REPORTER_DIR}"
python -m analyzer.main initial \
    --input-dir  "${SCRATCH_SCAN}" \
    --output-dir "${SCRATCH_ANALYSIS}" || die "Report generation failed"
echo "      ok"

# Derive slug
if [ "$MODE" = "image" ]; then
    SCAN_SLUG=$(echo "${TARGET}" | sed 's|.*/||' | sed 's/:/-/')
else
    if [ -n "${PROJECT_NAME:-}" ] && [ "${PROJECT_NAME}" != "unknown-project" ]; then
        SCAN_SLUG="${PROJECT_NAME}"
    else
        SCAN_SLUG=$(basename "${TARGET}")
    fi
fi

mkdir -p "${SCAN_OUTPUT_DIR}"

# Copy generated reports
cp -f "${SCRATCH_ANALYSIS}/initial-security-report.pdf"  "${SCAN_OUTPUT_DIR}/${SCAN_SLUG}-security-report.pdf"
cp -f "${SCRATCH_ANALYSIS}/initial-security-report.html" "${SCAN_OUTPUT_DIR}/${SCAN_SLUG}-security-report.html"

mkdir -p "${SCAN_OUTPUT_DIR}/data"

# Pretty-format JSON outputs before publishing
format_json() {
    local src="$1"
    local dst="$2"

    if jq . "$src" > "$dst"; then
        return 0
    else
        echo "Warning: Failed to format JSON: $src, copying raw file instead" >&2
        cp -f "$src" "$dst"
    fi
}

format_json "${SCRATCH_ANALYSIS}/initial-report-data.json" "${SCAN_OUTPUT_DIR}/data/${SCAN_SLUG}-report-data.json"
format_json "${SCRATCH_SCAN}/sbom-cyclonedx.json"          "${SCAN_OUTPUT_DIR}/data/${SCAN_SLUG}-sbom.json"
format_json "${SCRATCH_SCAN}/grype-sbom-vulns.json"        "${SCAN_OUTPUT_DIR}/data/${SCAN_SLUG}-vulns.json"

# Copy HTML inventory
cp -f "${SCRATCH_ANALYSIS}/sbom-inventory.html" "${SCAN_OUTPUT_DIR}/data/${SCAN_SLUG}-sbom.html"

echo ""
echo "Security scan complete."
echo ""
echo "Reports:"
find "${SCAN_OUTPUT_DIR}" -maxdepth 1 -type f -printf "  %f\n" | sort
echo "Data:"
find "${SCAN_OUTPUT_DIR}/data" -type f -printf "  %f\n" | sort
echo ""
echo "Artifacts will be available for 10 days."
