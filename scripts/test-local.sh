#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
IMAGE="rockpi-harden-test"
CONTAINER="rockpi-test"

# Build test image (pulls autohodl/clawd-starter-rockpi from DockerHub)
docker build -f "$REPO_DIR/Dockerfile.test" -t "$IMAGE" "$REPO_DIR"

# Clean up any previous run & start with systemd
docker rm -f "$CONTAINER" 2>/dev/null || true
docker run -d --name "$CONTAINER" --platform linux/arm64 --privileged \
  --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock \
  "$IMAGE"

# Wait for systemd to boot
echo "Waiting for systemd to boot..."
for i in $(seq 1 30); do
  if docker exec "$CONTAINER" systemctl is-system-running --wait 2>/dev/null | grep -qE "running|degraded"; then
    break
  fi
  sleep 1
done

# Copy scripts into container
docker cp "$REPO_DIR/scripts" "$CONTAINER:/opt/scripts"

# Create /run/sshd (on real hardware sshd is already running; in container /run is tmpfs)
docker exec "$CONTAINER" mkdir -p /run/sshd

# Run hardening
echo "=== Running harden-rockpi.sh ==="
docker exec "$CONTAINER" bash /opt/scripts/harden-rockpi.sh

# Start services that were installed at runtime (systemd doesn't auto-start them in Docker)
docker exec "$CONTAINER" systemctl daemon-reload
docker exec "$CONTAINER" systemctl start chrony || true

# Run verification
echo ""
echo "=== Running verify-hardening.sh ==="
docker exec "$CONTAINER" bash /opt/scripts/verify-hardening.sh
EXIT_CODE=$?

# Cleanup
docker stop "$CONTAINER" >/dev/null
docker rm "$CONTAINER" >/dev/null

exit $EXIT_CODE
