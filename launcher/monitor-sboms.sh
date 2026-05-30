#!/usr/bin/env bash
set -euo pipefail

IMAGE_SCANNER_BASE_DIR="${IMAGE_SCANNER_BASE_DIR:-$HOME/image-scanner-runtime}"
RESULTS_DIR="$IMAGE_SCANNER_BASE_DIR/results"
GRYPE_CACHE_DIR="$IMAGE_SCANNER_BASE_DIR/cache/grype"
MONITOR_IMAGE="${SBOM_MONITOR_IMAGE:-sbom-monitor:latest}"

mkdir -p "$RESULTS_DIR" "$GRYPE_CACHE_DIR"

if command -v sudo >/dev/null 2>&1; then
  sudo chown -R "$(id -u):$(id -g)" "$RESULTS_DIR" "$GRYPE_CACHE_DIR" || true
fi
chmod -R u+rwX,g+rwX "$RESULTS_DIR" "$GRYPE_CACHE_DIR" || true

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$RESULTS_DIR:/results" \
  -v "$GRYPE_CACHE_DIR:/cache/grype" \
  "$MONITOR_IMAGE" \
  python -m monitor.main /results
