#!/usr/bin/env bash
set -euo pipefail

HOST_USER="${SUDO_USER:-$(id -un)}"
HOST_UID="$(id -u "$HOST_USER")"
HOST_GID="$(id -g "$HOST_USER")"
HOST_HOME="$(getent passwd "$HOST_USER" | cut -d: -f6)"

IMAGE_SCANNER_BASE_DIR="${IMAGE_SCANNER_BASE_DIR:-$HOST_HOME/image-scanner-runtime}"
ORG_DATA_CURRENT_DIR="$IMAGE_SCANNER_BASE_DIR/org-data/current"
REPORTS_DIR="$IMAGE_SCANNER_BASE_DIR/security-reports"
CONSOLE_IMAGE="${ORG_SECURITY_CONSOLE_IMAGE:-org-security-console:latest}"
CONSOLE_PORT="${ORG_SECURITY_CONSOLE_PORT:-8090}"

mkdir -p "$ORG_DATA_CURRENT_DIR" "$REPORTS_DIR"
chown -R "$HOST_UID:$HOST_GID" "$REPORTS_DIR" || true
chmod -R u+rwX,g+rwX "$REPORTS_DIR" || true

echo "Org Security Console starting"
echo "Org data: $ORG_DATA_CURRENT_DIR"
echo "Reports: $REPORTS_DIR"
echo "Port: $CONSOLE_PORT"

docker run --rm \
  --user "$HOST_UID:$HOST_GID" \
  -p "$CONSOLE_PORT:8080" \
  -v "$ORG_DATA_CURRENT_DIR:/org-data/current:ro" \
  -v "$REPORTS_DIR:/reports" \
  "$CONSOLE_IMAGE"
