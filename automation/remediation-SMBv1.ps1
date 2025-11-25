<#
.SYNOPSIS
    Remediates the SMBv1 vulnerability by fully disabling the protocol.

.DESCRIPTION
    This script disables SMBv1 at the feature level and enforces secure
    registry settings for both the SMBv1 client and server components.

    This is the corrective counterpart to:
        SMBv1-Create-Vulnerability.ps1
#>

Write-Host "`n=== SMBv1 Remediation Starting ===" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Disable SMBv1 Feature
# -------------------------------------------------------------
Write-Host "[1/3] Disabling SMBv1 Windows Feature..." -ForegroundColor Yellow

try {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
    Write-Host "[+] SMBv1 Windows Optional Feature disabled." -ForegroundColor Green
}
catch {
    Write-Warning "[-] Failed to disable SMBv1 feature (possibly already disabled): $($_.Exception.Message)"
}

# -------------------------------------------------------------
# 2. Disable SMBv1 Client
# -------------------------------------------------------------
Write-Host "[2/3] Applying SMBv1 Client registry hardening..." -ForegroundColor Yellow

$ClientKeyPath       = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$ClientDriverPath    = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"

if (Test-Path $ClientKeyPath) {
    try {
        Set-ItemProperty -Path $ClientKeyPath -Name "AllowInsecureGuestAuth" -Value 0 -Force
        Write-Host "[+] Disabled insecure guest authentication." -ForegroundColor Green
    }
    catch {
        Write-Warning "[-] Failed to update client registry key: $($_.Exception.Message)"
    }
}

if (Test-Path $ClientDriverPath) {
    try {
        Set-ItemProperty -Path $ClientDriverPath -Name "Start" -Value 4 -Force
        Write-Host "[+] SMBv1 Client driver disabled (Start=4)." -ForegroundColor Green
    }
    catch {
        Write-Warning "[-] Failed to update SMBv1 driver registry key: $($_.Exception.Message)"
    }
}
else {
    Write-Host "[i] SMBv1 client driver path not found — may not exist on this system." -ForegroundColor Gray
}

# -------------------------------------------------------------
# 3. Disable SMBv1 Server
# -------------------------------------------------------------
Write-Host "[3/3] Applying SMBv1 Server registry hardening..." -ForegroundColor Yellow

$ServerKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

if (Test-Path $ServerKeyPath) {
    try {
        Set-ItemProperty -Path $ServerKeyPath -Name "SMB1" -Value 0 -Force
        Write-Host "[+] SMBv1 Server disabled (SMB1=0)." -ForegroundColor Green
    }
    catch {
        Write-Warning "[-] Failed to update SMBv1 server registry key: $($_.Exception.Message)"
    }
}
else {
    Write-Host "[i] SMBv1 server registry path not found — SMBv1 may not be installed." -ForegroundColor Gray
}

Write-Host "`n=== SMBv1 Remediation Complete ===" -ForegroundColor Cyan
Write-Host "A reboot is recommended to ensure all changes take effect.`n"
