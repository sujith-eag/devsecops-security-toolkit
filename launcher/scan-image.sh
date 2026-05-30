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
REPORTER_IMAGE="reporter-analyzer:latest"
TAR_RETENTION_MINUTES=1440

ARTIFACT_TYPE="${ARTIFACT_TYPE:-container_image}"
ARTIFACT_ROLE="${ARTIFACT_ROLE:-}"
PROJECT_ID="${PROJECT_ID:-}"
PROJECT_NAME="${PROJECT_NAME:-}"
PROJECT_TYPE="${PROJECT_TYPE:-}"
PROJECT_REPOSITORY="${PROJECT_REPOSITORY:-}"
PROJECT_BRANCH="${PROJECT_BRANCH:-}"
PROJECT_COMMIT="${PROJECT_COMMIT:-}"

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  HOST_UID="$(id -u "$SUDO_USER")"
  HOST_GID="$(id -g "$SUDO_USER")"
else
  HOST_UID="$(id -u)"
  HOST_GID="$(id -g)"
fi

fix_permissions() {
  local target="$1"
  if [ -e "$target" ]; then
    chown -R "$HOST_UID:$HOST_GID" "$target" || true
    chmod -R u+rwX,g+rwX "$target" || true
  fi
}

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not installed or not available"
  exit 1
fi

mkdir -p "$WORK_BASE" "$RESULTS_BASE" "$LOG_BASE" "$CACHE_BASE/grype"
fix_permissions "$BASE_DIR"

if ! docker image inspect "$SCANNER_IMAGE" >/dev/null 2>&1; then
  echo "ERROR: scanner image not found locally: $SCANNER_IMAGE"
  echo "Build it first, for example: docker build -t $SCANNER_IMAGE -f dockerfile ."
  exit 1
fi

if docker image inspect "$IMAGE_REF" >/dev/null 2>&1; then
  echo "Image exists locally, skipping pull: $IMAGE_REF"
  IMAGE_SOURCE="local"
else
  echo "Image not found locally, pulling: $IMAGE_REF"
  docker pull "$IMAGE_REF"
  IMAGE_SOURCE="registry"
fi

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

IMAGE_REF_NO_DIGEST="${IMAGE_REF%%@*}"
IMAGE_LAST_PART="${IMAGE_REF_NO_DIGEST##*/}"
if [[ "$IMAGE_LAST_PART" == *":"* ]]; then
  IMAGE_TAG="${IMAGE_LAST_PART##*:}"
  IMAGE_NAME="${IMAGE_REF_NO_DIGEST%:*}"
else
  IMAGE_TAG=""
  IMAGE_NAME="$IMAGE_REF_NO_DIGEST"
fi

SAFE_IMAGE_REF="$(echo "$IMAGE_REF" | sed 's#[/:@]#_#g' | sed 's#[^A-Za-z0-9_.-]#_#g')"
RUN_DIR="${SAFE_IMAGE_REF}__${SHORT_DIGEST}"
ARTIFACT_ID="$RUN_DIR"

WORK_DIR="$WORK_BASE/$RUN_DIR"
RESULT_DIR="$RESULTS_BASE/$RUN_DIR"
ANALYSIS_DIR="$RESULT_DIR/analysis"
IMAGE_TAR="$WORK_DIR/image.tar"
METADATA_FILE="$RESULT_DIR/metadata.json"
SCAN_LOG="$RESULT_DIR/host-scan.log"

mkdir -p "$WORK_DIR" "$RESULT_DIR" "$ANALYSIS_DIR"
fix_permissions "$WORK_DIR"
fix_permissions "$RESULT_DIR"
fix_permissions "$CACHE_BASE/grype"

cat > "$METADATA_FILE" <<EOF
{
  "schema_version": "1.0",
  "artifact_id": "$ARTIFACT_ID",
  "artifact_type": "$ARTIFACT_TYPE",
  "artifact_role": "$ARTIFACT_ROLE",
  "project": {
    "project_id": "$PROJECT_ID",
    "project_name": "$PROJECT_NAME",
    "project_type": "$PROJECT_TYPE",
    "project_repository": "$PROJECT_REPOSITORY",
    "project_branch": "$PROJECT_BRANCH",
    "project_commit": "$PROJECT_COMMIT"
  },
  "image": {
    "image_ref": "$IMAGE_REF",
    "image_source": "$IMAGE_SOURCE",
    "image_name": "$IMAGE_NAME",
    "image_tag": "$IMAGE_TAG",
    "repo_digest": "$REPO_DIGEST",
    "digest_value": "$DIGEST_VALUE",
    "short_digest": "$SHORT_DIGEST",
    "image_id": "$IMAGE_ID",
    "image_os": "$IMAGE_OS",
    "image_architecture": "$IMAGE_ARCH",
    "image_created": "$IMAGE_CREATED"
  },
  "scan": {
    "scan_timestamp_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "scanner_image": "$SCANNER_IMAGE",
    "reporter_image": "$REPORTER_IMAGE",
    "docker_version": "$(docker --version)",
    "host_architecture": "$(uname -m)",
    "host_uid": "$HOST_UID",
    "host_gid": "$HOST_GID"
  },
  "paths": {
    "base_dir": "$BASE_DIR",
    "work_dir": "$WORK_DIR",
    "result_dir": "$RESULT_DIR",
    "analysis_dir": "$ANALYSIS_DIR",
    "image_tar": "$IMAGE_TAR"
  }
}
EOF

fix_permissions "$METADATA_FILE"

{
  echo "Image reference: $IMAGE_REF"
  echo "Artifact ID: $ARTIFACT_ID"
  echo "Artifact type: $ARTIFACT_TYPE"
  echo "Digest: $DIGEST_VALUE"
  echo "Run dir: $RUN_DIR"
  echo "Base dir: $BASE_DIR"
  echo "Host UID:GID: $HOST_UID:$HOST_GID"
  echo "Work dir: $WORK_DIR"
  echo "Result dir: $RESULT_DIR"
  echo "Saving image tar..."
} | tee "$SCAN_LOG"

docker save "$IMAGE_REF" -o "$IMAGE_TAR"
fix_permissions "$IMAGE_TAR"

echo "Running scanner container..." | tee -a "$SCAN_LOG"

docker run --rm \
  --user "$HOST_UID:$HOST_GID" \
  -v "$WORK_DIR:/input:ro" \
  -v "$RESULT_DIR:/results" \
  -v "$CACHE_BASE/grype:/cache/grype" \
  -e XDG_CACHE_HOME=/cache \
  -e GRYPE_DB_CACHE_DIR=/cache/grype/db \
  "$SCANNER_IMAGE" \
  /scanner/scan-from-tar.sh /input/image.tar /results

fix_permissions "$RESULT_DIR"
fix_permissions "$CACHE_BASE/grype"

echo "Running reporter/analyzer container..." | tee -a "$SCAN_LOG"
mkdir -p "$ANALYSIS_DIR"
fix_permissions "$ANALYSIS_DIR"

docker run --rm \
  --user "$HOST_UID:$HOST_GID" \
  -v "$RESULT_DIR:/input:ro" \
  -v "$ANALYSIS_DIR:/output" \
  "$REPORTER_IMAGE" \
  python -m analyzer.main /input /output

fix_permissions "$RESULT_DIR"

echo "Cleaning tar files older than 24 hours" | tee -a "$SCAN_LOG"
find "$WORK_BASE" -name "image.tar" -type f -mmin +"$TAR_RETENTION_MINUTES" -delete
find "$WORK_BASE" -mindepth 1 -type d -empty -delete
fix_permissions "$BASE_DIR"

echo "Scan completed successfully"
echo "Results: $RESULT_DIR"