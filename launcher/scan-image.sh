#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="${1:-}"

if [ -z "$IMAGE_REF" ]; then
  echo "Usage: $0 <image-ref>"
  echo "Example: $0 nginx:latest"
  exit 1
fi

if [ -n "${IMAGE_SCANNER_BASE_DIR:-}" ]; then
  BASE_DIR="$IMAGE_SCANNER_BASE_DIR"
elif [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  BASE_DIR="$USER_HOME/image-scanner-runtime"
else
  BASE_DIR="$HOME/image-scanner-runtime"
fi

WORK_BASE="$BASE_DIR/work"
RESULTS_BASE="$BASE_DIR/results"
LOG_BASE="$BASE_DIR/logs"
CACHE_BASE="$BASE_DIR/cache"

SCANNER_IMAGE="image-sbom-vuln-scanner:latest"
TAR_RETENTION_MINUTES=1440

mkdir -p "$WORK_BASE" "$RESULTS_BASE" "$LOG_BASE" "$CACHE_BASE/grype"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not installed or not available"
  exit 1
fi

echo "Pulling image: $IMAGE_REF"
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

DIGEST_ALGO="${DIGEST_VALUE%%:*}"
DIGEST_HASH="${DIGEST_VALUE#*:}"
SHORT_DIGEST="${DIGEST_ALGO}_${DIGEST_HASH:0:12}"

SAFE_IMAGE_REF="$(echo "$IMAGE_REF" | sed 's#[/:@]#_#g' | sed 's#[^A-Za-z0-9_.-]#_#g')"
RUN_DIR="${SAFE_IMAGE_REF}__${SHORT_DIGEST}"

WORK_DIR="$WORK_BASE/$RUN_DIR"
RESULT_DIR="$RESULTS_BASE/$RUN_DIR"
IMAGE_TAR="$WORK_DIR/image.tar"
METADATA_FILE="$RESULT_DIR/metadata.json"
SCAN_LOG="$RESULT_DIR/host-scan.log"

mkdir -p "$WORK_DIR" "$RESULT_DIR"

cat > "$METADATA_FILE" <<EOF
{
  "image_ref": "$IMAGE_REF",
  "repo_digest": "$REPO_DIGEST",
  "digest_value": "$DIGEST_VALUE",
  "short_digest": "$SHORT_DIGEST",
  "image_id": "$IMAGE_ID",
  "image_os": "$IMAGE_OS",
  "image_architecture": "$IMAGE_ARCH",
  "image_created": "$IMAGE_CREATED",
  "scan_timestamp_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "host_architecture": "$(uname -m)",
  "docker_version": "$(docker --version)",
  "scanner_image": "$SCANNER_IMAGE",
  "base_dir": "$BASE_DIR",
  "work_dir": "$WORK_DIR",
  "result_dir": "$RESULT_DIR",
  "image_tar": "$IMAGE_TAR"
}
EOF

{
  echo "Image reference: $IMAGE_REF"
  echo "Digest: $DIGEST_VALUE"
  echo "Run dir: $RUN_DIR"
  echo "Base dir: $BASE_DIR"
  echo "Work dir: $WORK_DIR"
  echo "Result dir: $RESULT_DIR"
  echo "Saving image tar..."
} | tee "$SCAN_LOG"

docker save "$IMAGE_REF" -o "$IMAGE_TAR"

echo "Running scanner container..." | tee -a "$SCAN_LOG"

docker run --rm \
  -v "$WORK_DIR:/input:ro" \
  -v "$RESULT_DIR:/results" \
  -v "$CACHE_BASE/grype:/root/.cache/grype" \
  "$SCANNER_IMAGE" \
  /scanner/scan-from-tar.sh /input/image.tar /results

echo "Cleaning tar files older than 24 hours" | tee -a "$SCAN_LOG"
find "$WORK_BASE" -name "image.tar" -type f -mmin +"$TAR_RETENTION_MINUTES" -delete
find "$WORK_BASE" -mindepth 1 -type d -empty -delete

echo "Scan completed successfully"
echo "Results: $RESULT_DIR"
