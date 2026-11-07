#!/usr/bin/env bash
# ==============================================================================
# TrustShield Security Platform - Standalone Pillar 1 Sandboxed Launcher
# Launches Pillar 1 worker in a single-use gVisor (runsc) container with
# read-only rootfs, dropped capabilities, and a 15-second timeout watchdog.
# ==============================================================================

set -euo pipefail

IMAGE_NAME="${1:-trustshield-worker-pillar1:latest}"
CONTAINER_NAME="trustshield-detonation-$(date +%s)"

echo "[*] Launching sandboxed detonation worker: ${CONTAINER_NAME}"
echo "[*] Sandbox: gVisor (runsc) | RootFS: Read-Only | Caps: Dropped [ALL]"

# 1. Start container with gVisor isolation profile
docker run -d \
  --name "${CONTAINER_NAME}" \
  --runtime=runsc \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --tmpfs /dev/shm:rw,noexec,nosuid,size=512m \
  --tmpfs /app/.cache:rw,noexec,nosuid,size=256m \
  --cpus=2.0 \
  --memory=2048m \
  --pids-limit=150 \
  --network=trustshield-isolated-egress \
  -e KAFKA_BROKERS="kafka:9092" \
  -e SCANNER_DETONATION_TIMEOUT_SEC=15 \
  "${IMAGE_NAME}"

# 2. Watchdog: Hard 15-Second Timeout Termination
(
  sleep 15
  if docker ps -q --filter "name=${CONTAINER_NAME}" | grep -q .; then
    echo "[-] [Watchdog Alert] 15-second hard timeout reached for ${CONTAINER_NAME}. Forcing destruction..."
    docker kill "${CONTAINER_NAME}" > /dev/null 2>&1 || true
    docker rm -f "${CONTAINER_NAME}" > /dev/null 2>&1 || true
    echo "[+] Container ${CONTAINER_NAME} safely destroyed."
  fi
) &

# 3. Follow logs until completion or timeout
echo "[*] Following execution logs..."
docker logs -f "${CONTAINER_NAME}" || true

# 4. Clean up container upon termination
docker rm -f "${CONTAINER_NAME}" > /dev/null 2>&1 || true
echo "[+] Detonation cycle completed."

