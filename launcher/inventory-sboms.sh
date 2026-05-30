#!/usr/bin/env bash
set -euo pipefail

HOST_USER="${SUDO_USER:-$(id -un)}"
HOST_UID="$(id -u "$HOST_USER")"
HOST_GID="$(id -g "$HOST_USER")"
HOST_HOME="$(getent passwd "$HOST_USER" | cut -d: -f6)"

IMAGE_SCANNER_BASE_DIR="${IMAGE_SCANNER_BASE_DIR:-$HOST_HOME/image-scanner-runtime}"
RESULTS_DIR="$IMAGE_SCANNER_BASE_DIR/results"
INVENTORY_DIR="$IMAGE_SCANNER_BASE_DIR/inventory"
INVENTORY_IMAGE="${SBOM_INVENTORY_IMAGE:-sbom-inventory:latest}"

echo "SBOM inventory starting"
echo "Host user: $HOST_USER"
echo "Host UID:GID: $HOST_UID:$HOST_GID"
echo "Base dir: $IMAGE_SCANNER_BASE_DIR"
echo "Results dir: $RESULTS_DIR"
echo "Inventory dir: $INVENTORY_DIR"
echo "Inventory image: $INVENTORY_IMAGE"

mkdir -p "$RESULTS_DIR" "$INVENTORY_DIR"

chown -R "$HOST_UID:$HOST_GID" "$RESULTS_DIR" "$INVENTORY_DIR" || true
chmod -R u+rwX,g+rwX "$RESULTS_DIR" "$INVENTORY_DIR" || true

echo "Result folders found:"
find "$RESULTS_DIR" -maxdepth 1 -mindepth 1 -type d -printf "  %f\n" || true

docker run --rm \
  --user "$HOST_UID:$HOST_GID" \
  -v "$RESULTS_DIR:/results" \
  -v "$INVENTORY_DIR:/inventory" \
  "$INVENTORY_IMAGE" \
  python -m inventory.main /results --inventory-dir /inventory
