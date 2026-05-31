#!/usr/bin/env bash

init_environment() {
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

  SCANNER_IMAGE="${SCANNER_IMAGE:-image-sbom-vuln-scanner:latest}"
  REPORTER_IMAGE="${REPORTER_IMAGE:-reporter-analyzer:latest}"
  TAR_RETENTION_MINUTES="${TAR_RETENTION_MINUTES:-1440}"

  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    HOST_UID="$(id -u "$SUDO_USER")"
    HOST_GID="$(id -g "$SUDO_USER")"
  else
    HOST_UID="$(id -u)"
    HOST_GID="$(id -g)"
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is not installed or not available"
    exit 1
  fi
}

prepare_runtime_dirs() {
  mkdir -p "$WORK_BASE" "$RESULTS_BASE" "$LOG_BASE" "$CACHE_BASE/grype" "$CACHE_BASE/syft"
  fix_permissions "$BASE_DIR"
  fix_permissions "$CACHE_BASE"
}

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

sanitize_name() {
  echo "$1" | sed 's#[/:@ ]#_#g' | sed 's#[^A-Za-z0-9_.-]#_#g'
}

fix_permissions() {
  local target="$1"
  if [ -e "$target" ]; then
    chown -R "$HOST_UID:$HOST_GID" "$target" 2>/dev/null || true
    chmod -R u+rwX,g+rwX "$target" 2>/dev/null || true
  fi
}

run_reporter() {
  local result_dir="$1"
  local analysis_dir="$result_dir/analysis"
  local scan_log="$result_dir/host-scan.log"

  mkdir -p "$analysis_dir"
  fix_permissions "$analysis_dir"

  echo "Running reporter/analyzer container..." | tee -a "$scan_log"
  docker run --rm \
    --user "$HOST_UID:$HOST_GID" \
    -v "$result_dir:/input:ro" \
    -v "$analysis_dir:/output" \
    "$REPORTER_IMAGE" \
    python -m analyzer.main /input /output

  fix_permissions "$analysis_dir"
}

cleanup_workdirs() {
  echo "Cleaning tar files older than 24 hours"
  find "$WORK_BASE" -name "image.tar" -type f -mmin +"$TAR_RETENTION_MINUTES" -delete 2>/dev/null || true
  find "$WORK_BASE" -mindepth 1 -type d -empty -delete 2>/dev/null || true
}
