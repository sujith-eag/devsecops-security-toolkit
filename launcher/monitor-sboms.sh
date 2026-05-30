#!/usr/bin/env bash
set -euo pipefail

HOST_USER="${SUDO_USER:-$(id -un)}"
HOST_UID="$(id -u "$HOST_USER")"
HOST_GID="$(id -g "$HOST_USER")"
HOST_HOME="$(getent passwd "$HOST_USER" | cut -d: -f6)"

IMAGE_SCANNER_BASE_DIR="${IMAGE_SCANNER_BASE_DIR:-$HOST_HOME/image-scanner-runtime}"
RESULTS_DIR="$IMAGE_SCANNER_BASE_DIR/results"
GRYPE_CACHE_DIR="$IMAGE_SCANNER_BASE_DIR/cache/grype"
MONITORING_DIR="$IMAGE_SCANNER_BASE_DIR/monitoring"
MONITOR_IMAGE="${SBOM_MONITOR_IMAGE:-sbom-monitor:latest}"

echo "SBOM monitor starting"
echo "Host user: $HOST_USER"
echo "Host UID:GID: $HOST_UID:$HOST_GID"
echo "Base dir: $IMAGE_SCANNER_BASE_DIR"
echo "Results dir: $RESULTS_DIR"
echo "Monitoring dir: $MONITORING_DIR"
echo "Grype cache dir: $GRYPE_CACHE_DIR"
echo "Monitor image: $MONITOR_IMAGE"

mkdir -p "$RESULTS_DIR" "$GRYPE_CACHE_DIR" "$MONITORING_DIR"

chown -R "$HOST_UID:$HOST_GID" "$RESULTS_DIR" "$GRYPE_CACHE_DIR" "$MONITORING_DIR" || true
chmod -R u+rwX,g+rwX "$RESULTS_DIR" "$GRYPE_CACHE_DIR" "$MONITORING_DIR" || true

echo "Result folders found:"
find "$RESULTS_DIR" -maxdepth 1 -mindepth 1 -type d -printf "  %f\n" || true

docker run --rm \
  --user "$HOST_UID:$HOST_GID" \
  -v "$RESULTS_DIR:/results" \
  -v "$MONITORING_DIR:/monitoring" \
  -v "$GRYPE_CACHE_DIR:/cache/grype" \
  "$MONITOR_IMAGE" \
  python -m monitor.main /results --monitoring-dir /monitoring
