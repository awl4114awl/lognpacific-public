#!/bin/bash
#
# remediation-openssl-3.0.5-install.sh
# ------------------------------------
# Securely installs OpenSSL 3.0.5 from source and configures the system
# to use the updated library version.
#
# This script is intended as a remediation step after intentionally
# introducing outdated/insecure OpenSSL versions in lab environments.
#

set -e  # Exit on errors

echo -e "\n=== OpenSSL 3.0.5 Installation (Remediation) Starting ===\n"

# -------------------------------------------------------------
# 1. Install dependencies
# -------------------------------------------------------------
echo "[1/6] Installing required dependencies..."
sudo apt update -y
sudo apt install -y build-essential checkinstall zlib1g-dev wget
echo "✓ Dependencies installed."

# -------------------------------------------------------------
# 2. Download OpenSSL 3.0.5
# -------------------------------------------------------------
SRC_DIR="/usr/local/src"
TAR_FILE="openssl-3.0.5.tar.gz"
OPENSSL_URL="https://www.openssl.org/source/openssl-3.0.5.tar.gz"

echo "[2/6] Downloading OpenSSL 3.0.5..."
sudo mkdir -p "$SRC_DIR"
sudo wget -q -O "$SRC_DIR/$TAR_FILE" "$OPENSSL_URL"

if [[ $? -ne 0 ]]; then
    echo "✗ Failed to download OpenSSL. Check connectivity or URL."
    exit 1
fi
echo "✓ Download complete."

# -------------------------------------------------------------
# 3. Extract package
# -------------------------------------------------------------
echo "[3/6] Extracting package..."
cd "$SRC_DIR"
sudo tar -xf "$TAR_FILE"
echo "✓ Extraction complete."

# -------------------------------------------------------------
# 4. Compile and install
# -------------------------------------------------------------
echo "[4/6] Configuring, compiling, and installing OpenSSL..."
cd "$SRC_DIR/openssl-3.0.5"

sudo ./config --prefix=/usr/local/openssl-3.0.5 --openssldir=/usr/local/openssl-3.0.5
sudo make -j"$(nproc)"
sudo make install
echo "✓ OpenSSL installed."

# -------------------------------------------------------------
# 5. Configure library path
# -------------------------------------------------------------
echo "[5/6] Updating library paths..."
echo "/usr/local/lib64" | sudo tee /etc/ld.so.conf.d/openssl-3.conf >/dev/null
sudo ldconfig
echo "✓ Library paths updated."

# -------------------------------------------------------------
# 6. Verify version
# -------------------------------------------------------------
echo "[6/6] Verifying OpenSSL installation..."
/usr/local/bin/openssl version || {
    echo "✗ OpenSSL binary not found at /usr/local/bin/openssl"
    exit 1
}
echo "✓ Installed OpenSSL version: $(/usr/local/bin/openssl version)"

echo -e "\n=== OpenSSL 3.0.5 Installation Complete ==="
echo "A system reboot is recommended.\n"

# Usage (kept for repo completeness)
# -----------------------------------
# wget https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/main/automation/remediation-openssl-3.0.5-install.sh --no-check-certificate
# chmod +x remediation-openssl-3.0.5-install.sh
# ./remediation-openssl-3.0.5-install.sh
