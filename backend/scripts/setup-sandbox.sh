#!/usr/bin/env bash
# ==============================================================================
# TrustShield Security Platform - gVisor (runsc) Sandbox Setup Script
# Configures hardware/kernel virtualization isolation for Pillar 1 detonation.
# Target OS: Ubuntu 22.04+ / Debian 12+ (x86_64 / arm64)
# ==============================================================================

set -euo pipefail

echo "[*] TrustShield: Initializing gVisor (runsc) MicroVM / Application Sandbox..."

# 1. Verify Root Privileges
if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: This script must be run as root (use sudo)." >&2
  exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  GVISOR_ARCH="x86_64" ;;
  aarch64) GVISOR_ARCH="arm64" ;;
  *) echo "[-] Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# 2. Download and install latest official Google gVisor runsc binary
URL="https://storage.googleapis.com/gvisor/releases/release/latest/${GVISOR_ARCH}"
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

echo "[*] Downloading runsc from Google gVisor release storage..."
curl -fsSL "${URL}/runsc" -o runsc
curl -fsSL "${URL}/runsc.sha512" -o runsc.sha512

echo "[*] Verifying cryptographic SHA512 checksum..."
sha512sum -c runsc.sha512

chmod a+rx runsc
mv runsc /usr/local/bin/runsc

echo "[+] Successfully installed /usr/local/bin/runsc version: $(/usr/local/bin/runsc --version | head -n 1)"

# 3. Register runsc OCI runtime in Docker daemon.json
DOCKER_CONFIG="/etc/docker/daemon.json"
mkdir -p /etc/docker

if [ -f "$DOCKER_CONFIG" ]; then
  echo "[*] Updating existing ${DOCKER_CONFIG}..."
  # Use python to safely inject runtime without corrupting existing JSON
  python3 -c "
import json
try:
    with open('${DOCKER_CONFIG}', 'r') as f:
        data = json.load(f)
except Exception:
    data = {}
runtimes = data.setdefault('runtimes', {})
runtimes['runsc'] = {'path': '/usr/local/bin/runsc'}
with open('${DOCKER_CONFIG}', 'w') as f:
    json.dump(data, f, indent=2)
"
else
  echo "[*] Creating new ${DOCKER_CONFIG}..."
  cat <<EOF > "$DOCKER_CONFIG"
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc"
    }
  }
}
EOF
fi

# 4. Restart Docker daemon to reload runtime configuration
echo "[*] Restarting Docker service..."
systemctl restart docker

# 5. Execute Self-Test Assertion inside gVisor sandbox
echo "[*] Running gVisor verification container..."
if docker run --rm --runtime=runsc hello-world > /dev/null 2>&1; then
  echo "[+] gVisor (runsc) is successfully configured and active in Docker!"
else
  echo "[-] Warning: gVisor runtime check returned non-zero. Check 'dmesg' or Docker daemon logs."
  exit 1
fi

echo "[+] Setup completed. You can now run Pillar 1 in strict sandboxed mode using 'docker-compose -f docker-compose.yml -f docker-compose.sandbox.yml up'."

