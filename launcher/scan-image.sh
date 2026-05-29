#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="${1:-}"

if [ -z "$IMAGE_REF" ]; then
  echo "Usage: $0 <image-ref>"
  echo "Example: $0 nginx:latest"
  exit 1
fi

BASE_DIR="/opt/image-scanner"
WORK_BASE="$BASE_DIR/work"
RESULTS_BASE="$BASE_DIR/results"
LOG_BASE="$BASE_DIR/logs"
SCANNER_IMAGE="image-sbom-vuln-scanner:latest"
TAR_RETENTION_DAYS=1

mkdir -p "$WORK_BASE" "$RESULTS_BASE" "$LOG_BASE"

docker pull "$IMAGE_REF"

REPO_DIGEST="$(docker inspect --format='{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "$IMAGE_REF" || true)"
IMAGE_ID="$(docker inspect --format='{{.Id}}' "$IMAGE_REF")"
IMAGE_OS="$(docker inspect --format='{{.Os}}' "$IMAGE_REF")"
IMAGE_ARCH="$(docker inspect --format='{{.Architecture}}' "$IMAGE_REF")"
IMAGE_CREATED="$(docker inspect --format='{{.Created}}' "$IMAGE_REF")"

if [ -n "$REPO_DIGEST" ]; then
  DIGEST_VALUE="${REPO_DIGEST#*@}"
else
  DIGEST_VALUE="$IMAGE_ID"
fi

DIGEST_DIR="$(echo "$DIGEST_VALUE" | sed 's/:/_/g')"

WORK_DIR="$WORK_BASE/$DIGEST_DIR"
RESULT_DIR="$RESULTS_BASE/$DIGEST_DIR"
IMAGE_TAR="$WORK_DIR/image.tar"
METADATA_FILE="$RESULT_DIR/metadata.json"
SCAN_LOG="$RESULT_DIR/host-scan.log"

mkdir -p "$WORK_DIR" "$RESULT_DIR"

cat > "$METADATA_FILE" <<EOF
{
  "image_ref": "$IMAGE_REF",
  "repo_digest": "$REPO_DIGEST",
  "digest_value": "$DIGEST_VALUE",
  "image_id": "$IMAGE_ID",
  "image_os": "$IMAGE_OS",
  "image_architecture": "$IMAGE_ARCH",
  "image_created": "$IMAGE_CREATED",
  "scan_timestamp_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "host_architecture": "$(uname -m)",
  "docker_version": "$(docker --version)",
  "scanner_image": "$SCANNER_IMAGE",
  "work_dir": "$WORK_DIR",
  "result_dir": "$RESULT_DIR",
  "image_tar": "$IMAGE_TAR"
}
EOF

{
  echo "Image reference: $IMAGE_REF"
  echo "Digest: $DIGEST_VALUE"
  echo "Work dir: $WORK_DIR"
  echo "Result dir: $RESULT_DIR"
  echo "Saving image tar..."
} | tee "$SCAN_LOG"

docker save "$IMAGE_REF" -o "$IMAGE_TAR"

echo "Running scanner container..." | tee -a "$SCAN_LOG"

docker run --rm \
  -v "$WORK_DIR:/input:ro" \
  -v "$RESULT_DIR:/results" \
  "$SCANNER_IMAGE" \
  /scanner/scan-from-tar.sh /input/image.tar /results

echo "Cleaning tar files older than $TAR_RETENTION_DAYS day(s)" | tee -a "$SCAN_LOG"
find "$WORK_BASE" -name "image.tar" -type f -mtime +"$TAR_RETENTION_DAYS" -delete

echo "Scan completed successfully"
echo "Results: $RESULT_DIR"
