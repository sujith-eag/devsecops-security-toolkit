#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat <<EOF
Usage:
  $0 image <image-ref>
  $0 source <local-source-dir>

Examples:
  $0 image nginx:latest
  $0 image image-sbom-vuln-scanner:latest
  $0 source /path/to/repo
EOF
}

SCAN_TYPE="${1:-}"
TARGET="${2:-}"

if [ -z "$SCAN_TYPE" ] || [ -z "$TARGET" ]; then
  usage
  exit 1
fi

init_environment
prepare_runtime_dirs

PROJECT_ID="${PROJECT_ID:-}"
PROJECT_NAME="${PROJECT_NAME:-}"
PROJECT_TYPE="${PROJECT_TYPE:-}"
PROJECT_REPOSITORY="${PROJECT_REPOSITORY:-}"
PROJECT_BRANCH="${PROJECT_BRANCH:-}"
PROJECT_COMMIT="${PROJECT_COMMIT:-}"
ARTIFACT_ROLE="${ARTIFACT_ROLE:-}"

write_metadata_image() {
  local metadata_file="$1"
  cat > "$metadata_file" <<EOF
{
  "schema_version": "1.0",
  "artifact_id": "$ARTIFACT_ID",
  "artifact_type": "container_image",
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
    "scan_type": "image",
    "scan_timestamp_utc": "$(timestamp_utc)",
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
}

write_metadata_source() {
  local metadata_file="$1"
  cat > "$metadata_file" <<EOF
{
  "schema_version": "1.0",
  "artifact_id": "$ARTIFACT_ID",
  "artifact_type": "source_project",
  "artifact_role": "$ARTIFACT_ROLE",
  "project": {
    "project_id": "$PROJECT_ID",
    "project_name": "$PROJECT_NAME",
    "project_type": "$PROJECT_TYPE",
    "project_repository": "$EFFECTIVE_PROJECT_REPOSITORY",
    "project_branch": "$EFFECTIVE_PROJECT_BRANCH",
    "project_commit": "$EFFECTIVE_PROJECT_COMMIT"
  },
  "source": {
    "source_path": "$SOURCE_PATH",
    "source_repository": "$SOURCE_REPOSITORY",
    "source_branch": "$SOURCE_BRANCH",
    "source_tag": "$SOURCE_TAG",
    "source_commit": "$SOURCE_COMMIT",
    "source_commit_short": "$SOURCE_COMMIT_SHORT"
  },
  "scan": {
    "scan_type": "source",
    "scan_timestamp_utc": "$(timestamp_utc)",
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
    "analysis_dir": "$ANALYSIS_DIR"
  }
}
EOF
}

scan_container_image() {
  IMAGE_REF="$TARGET"

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

  SAFE_IMAGE_REF="$(sanitize_name "$IMAGE_REF")"
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
  fix_permissions "$CACHE_BASE"

  write_metadata_image "$METADATA_FILE"
  fix_permissions "$METADATA_FILE"

  {
    echo "Scan type: image"
    echo "Image reference: $IMAGE_REF"
    echo "Artifact ID: $ARTIFACT_ID"
    echo "Digest: $DIGEST_VALUE"
    echo "Base dir: $BASE_DIR"
    echo "Work dir: $WORK_DIR"
    echo "Result dir: $RESULT_DIR"
    echo "Saving image tar..."
  } | tee "$SCAN_LOG"

  docker save "$IMAGE_REF" -o "$IMAGE_TAR"
  fix_permissions "$IMAGE_TAR"

  echo "Running scanner container for image tar..." | tee -a "$SCAN_LOG"
  docker run --rm \
    --user "$HOST_UID:$HOST_GID" \
    -v "$WORK_DIR:/input:ro" \
    -v "$RESULT_DIR:/results" \
    -v "$CACHE_BASE:/cache" \
    -e XDG_CACHE_HOME=/cache \
    -e GRYPE_DB_CACHE_DIR=/cache/grype/db \
    "$SCANNER_IMAGE" \
    /scanner/scan-from-tar.sh /input/image.tar /results

  fix_permissions "$RESULT_DIR"
  run_reporter "$RESULT_DIR"
  cleanup_workdirs
  fix_permissions "$BASE_DIR"

  echo "Scan completed successfully"
  echo "Results: $RESULT_DIR"
}

scan_source_directory() {
  SOURCE_PATH="$(cd "$TARGET" && pwd -P)"
  SOURCE_NAME="$(basename "$SOURCE_PATH")"

  SOURCE_REPOSITORY=""
  SOURCE_BRANCH=""
  SOURCE_TAG=""
  SOURCE_COMMIT=""
  SOURCE_COMMIT_SHORT=""

  if command -v git >/dev/null 2>&1 && git -C "$SOURCE_PATH" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    SOURCE_REPOSITORY="$(git -C "$SOURCE_PATH" config --get remote.origin.url || true)"
    SOURCE_BRANCH="$(git -C "$SOURCE_PATH" rev-parse --abbrev-ref HEAD || true)"
    SOURCE_TAG="$(git -C "$SOURCE_PATH" describe --tags --exact-match 2>/dev/null || true)"
    SOURCE_COMMIT="$(git -C "$SOURCE_PATH" rev-parse HEAD || true)"
    SOURCE_COMMIT_SHORT="$(git -C "$SOURCE_PATH" rev-parse --short=12 HEAD || true)"
  fi

  EFFECTIVE_PROJECT_REPOSITORY="${PROJECT_REPOSITORY:-$SOURCE_REPOSITORY}"
  EFFECTIVE_PROJECT_BRANCH="${PROJECT_BRANCH:-$SOURCE_BRANCH}"
  EFFECTIVE_PROJECT_COMMIT="${PROJECT_COMMIT:-$SOURCE_COMMIT}"

  SAFE_SOURCE_NAME="$(sanitize_name "$SOURCE_NAME")"
  SAFE_REF="$(sanitize_name "${SOURCE_TAG:-${SOURCE_BRANCH:-local}}")"
  if [ -n "$SOURCE_COMMIT_SHORT" ]; then
    RUN_DIR="${SAFE_SOURCE_NAME}__${SAFE_REF}__${SOURCE_COMMIT_SHORT}"
  else
    RUN_DIR="${SAFE_SOURCE_NAME}__local"
  fi
  ARTIFACT_ID="$RUN_DIR"

  WORK_DIR="$WORK_BASE/$RUN_DIR"
  RESULT_DIR="$RESULTS_BASE/$RUN_DIR"
  ANALYSIS_DIR="$RESULT_DIR/analysis"
  METADATA_FILE="$RESULT_DIR/metadata.json"
  SCAN_LOG="$RESULT_DIR/host-scan.log"

  mkdir -p "$WORK_DIR" "$RESULT_DIR" "$ANALYSIS_DIR"

  fix_permissions "$WORK_DIR"
  fix_permissions "$RESULT_DIR"
  fix_permissions "$CACHE_BASE"

  write_metadata_source "$METADATA_FILE"
  fix_permissions "$METADATA_FILE"

  {
    echo "Scan type: source"
    echo "Source path: $SOURCE_PATH"
    echo "Artifact ID: $ARTIFACT_ID"
    echo "Repository: $SOURCE_REPOSITORY"
    echo "Branch: $SOURCE_BRANCH"
    echo "Commit: $SOURCE_COMMIT"
    echo "Base dir: $BASE_DIR"
    echo "Result dir: $RESULT_DIR"
  } | tee "$SCAN_LOG"

  echo "Running scanner container for source directory..." | tee -a "$SCAN_LOG"
  docker run --rm \
    --user "$HOST_UID:$HOST_GID" \
    -v "$SOURCE_PATH:/input/source:ro" \
    -v "$RESULT_DIR:/results" \
    -v "$CACHE_BASE:/cache" \
    -e XDG_CACHE_HOME=/cache \
    -e GRYPE_DB_CACHE_DIR=/cache/grype/db \
    "$SCANNER_IMAGE" \
    /scanner/scan-from-dir.sh /input/source /results

  fix_permissions "$RESULT_DIR"
  run_reporter "$RESULT_DIR"
  cleanup_workdirs
  fix_permissions "$BASE_DIR"

  echo "Scan completed successfully"
  echo "Results: $RESULT_DIR"
}

case "$SCAN_TYPE" in
  image)
    scan_container_image
    ;;
  source|repo|dir)
    if [ ! -d "$TARGET" ]; then
      echo "ERROR: source directory not found: $TARGET"
      exit 1
    fi
    scan_source_directory
    ;;
  *)
    echo "ERROR: unsupported scan type: $SCAN_TYPE"
    usage
    exit 1
    ;;
esac
