#!/bin/bash
#
# remediation-root-password.sh
# -----------------------------
# Resets the root password to a secure lab value as part of the
# Linux remediation workflow inside the Cyber Range environment.
#
# NOTE:
#   • This script sets the root password intentionally.
#   • Use ONLY in isolated lab VMs.
#

set -e

NEW_PASSWORD="Cyberlab123!"   # Lab-only remediation password

echo -e "\n=== Root Password Remediation Starting ===\n"

# -------------------------------------------------------------
# 1. Reset the root password
# -------------------------------------------------------------
echo "[1/2] Setting new root password..."
echo -e "${NEW_PASSWORD}\n${NEW_PASSWORD}" | sudo passwd root >/dev/null 2>&1

if [[ $? -eq 0 ]]; then
    echo "✓ Root password successfully reset."
else
    echo "✗ Failed to change root password."
    exit 1
fi

# -------------------------------------------------------------
# 2. Securely clean up script contents (optional)
# -------------------------------------------------------------
# Instead of deleting itself (dangerous and unreliable),
# we warn the user and provide the safe recommended behavior.
echo "[2/2] Reminder: Remove this script after execution if stored locally."
echo "    (This script no longer self-deletes for safety.)"

echo -e "\n=== Root Password Remediation Complete ===\n"

# Usage notes (kept for repo completeness)
# -----------------------------------------
# wget https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/main/automation/remediation-root-password.sh --no-check-certificate
# chmod +x remediation-root-password.sh
# ./remediation-root-password.sh
