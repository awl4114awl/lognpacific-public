#!/bin/bash
#
# ubuntu-os-update-remediation.sh
# --------------------------------
# Remediates outdated Ubuntu packages (including OpenSSL)
# by performing a full OS update and rebooting.
#
# Intended for Cyber Range vulnerability remediation labs.
#

set -e

echo -e "\n=== Ubuntu OS Update Remediation Starting ===\n"

# -------------------------------------------------------------
# 1. Ensure script is run with sudo/root
# -------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "✗ This script must be run as root (sudo)."
    exit 1
fi

# -------------------------------------------------------------
# 2. Show current OpenSSL version
# -------------------------------------------------------------
echo "[1/4] Checking current OpenSSL version..."
if command -v openssl >/dev/null 2>&1; then
    openssl version
else
    echo "ℹ OpenSSL not installed."
fi

# -------------------------------------------------------------
# 3. Update package lists
# -------------------------------------------------------------
echo -e "\n[2/4] Updating package lists..."
apt update -y && echo "✓ Package lists updated."

# -------------------------------------------------------------
# 4. Full OS upgrade
# -------------------------------------------------------------
echo -e "\n[3/4] Performing full upgrade..."
apt full-upgrade -y && echo "✓ System fully upgraded."

# -------------------------------------------------------------
# 5. Confirm OpenSSL version again
# -------------------------------------------------------------
echo -e "\n[4/4] Verifying updated OpenSSL version..."
if command -v openssl >/dev/null 2>&1; then
    openssl version
else
    echo "ℹ OpenSSL still not installed (expected only in minimal images)."
fi

# -------------------------------------------------------------
# 6. Reboot system
# -------------------------------------------------------------
echo -e "\n=== Rebooting system to apply all updates... ==="
sleep 2
reboot
