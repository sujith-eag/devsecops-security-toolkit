#!/usr/bin/env bash
set -euo pipefail

# Launcher for org-data generation.
#
# Resolves the real host user even when run with sudo, prepares runtime folders,
# fixes ownership/permissions, mounts results/org-data/Grype cache directories,
# and runs the org-data generator container as the host UID/GID.

HOST_USER="${SUDO_USER:-$(id -un)}"
HOST_UID="$(id -u "$HOST_USER")"
HOST_GID="$(id -g "$HOST_USER")"
HOST_HOME="$(getent passwd "$HOST_USER" | cut -d: -f6)"

IMAGE_SCANNER_BASE_DIR="${IMAGE_SCANNER_BASE_DIR:-$HOST_HOME/image-scanner-runtime}"
RESULTS_DIR="$IMAGE_SCANNER_BASE_DIR/results"
ORG_DATA_DIR="$IMAGE_SCANNER_BASE_DIR/org-data"
GRYPE_CACHE_DIR="$IMAGE_SCANNER_BASE_DIR/cache/grype"
ORG_DATA_IMAGE="${ORG_DATA_IMAGE:-org-data-generator:latest}"
SKIP_VULN_REFRESH="${SKIP_VULN_REFRESH:-false}"

mkdir -p "$RESULTS_DIR" "$ORG_DATA_DIR" "$GRYPE_CACHE_DIR"
chown -R "$HOST_UID:$HOST_GID" "$RESULTS_DIR" "$ORG_DATA_DIR" "$GRYPE_CACHE_DIR" || true
chmod -R u+rwX,g+rwX "$RESULTS_DIR" "$ORG_DATA_DIR" "$GRYPE_CACHE_DIR" || true

echo "Org data generation starting"
echo "Host user: $HOST_USER"
echo "Base dir: $IMAGE_SCANNER_BASE_DIR"
echo "Results dir: $RESULTS_DIR"
echo "Org data dir: $ORG_DATA_DIR"
echo "Grype cache dir: $GRYPE_CACHE_DIR"
echo "Image: $ORG_DATA_IMAGE"

ARGS=(python -m orgdata.main /results --org-data-dir /org-data)
if [ "$SKIP_VULN_REFRESH" = "true" ]; then
  ARGS+=(--skip-vuln-refresh)
fi

docker run --rm \
  --user "$HOST_UID:$HOST_GID" \
  -v "$RESULTS_DIR:/results" \
  -v "$ORG_DATA_DIR:/org-data" \
  -v "$GRYPE_CACHE_DIR:/cache/grype" \
  -e GRYPE_DB_CACHE_DIR=/cache/grype/db \
  "$ORG_DATA_IMAGE" \
  "${ARGS[@]}"
