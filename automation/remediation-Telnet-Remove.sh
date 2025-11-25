#!/bin/bash
#
# remediation-Telnet-Remove.sh
# ----------------------------
# Removes Telnet server components, disables inetd, and cleans up
# all related packages as part of a Linux remediation workflow.
#

echo -e "\n=== Telnet Remediation Starting ===\n"

# -------------------------------------------------------------
# 1. Stop inetd service
# -------------------------------------------------------------
echo "[1/5] Stopping inetd.service..."
if sudo systemctl stop inetd.service 2>/dev/null; then
    echo "✓ inetd.service stopped."
else
    echo "ℹ inetd.service not running or not found."
fi

# -------------------------------------------------------------
# 2. Disable inetd service
# -------------------------------------------------------------
echo "[2/5] Disabling inetd.service..."
if sudo systemctl disable inetd.service 2>/dev/null; then
    echo "✓ inetd.service disabled."
else
    echo "ℹ inetd.service does not exist or was already disabled."
fi

# -------------------------------------------------------------
# 3. Remove Telnet packages
# -------------------------------------------------------------
echo "[3/5] Removing telnetd and inetutils-inetd..."
sudo apt remove --purge -y telnetd inetutils-inetd 2>/dev/null
echo "✓ Telnet packages removed (if installed)."

# -------------------------------------------------------------
# 4. Autoremove unused dependencies
# -------------------------------------------------------------
echo "[4/5] Cleaning up unused dependencies..."
sudo apt autoremove -y
echo "✓ Autoremove complete."

# -------------------------------------------------------------
# 5. Update package lists
# -------------------------------------------------------------
echo "[5/5] Updating package lists..."
sudo apt update -y
echo "✓ Package list updated."

echo -e "\n=== Telnet Remediation Complete ===\n"

# Usage instructions (kept for portfolio completeness)
# -------------------------------------------------------------
# wget https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/main/automation/remediation-Telnet-Remove.sh --no-check-certificate
# chmod +x remediation-Telnet-Remove.sh
# ./remediation-Telnet-Remove.sh
