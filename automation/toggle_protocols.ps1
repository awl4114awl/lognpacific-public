<#
.SYNOPSIS
    Enables or disables legacy SSL/TLS protocols on Windows systems.

.DESCRIPTION
    This script toggles insecure cryptographic protocols (SSL 2.0, SSL 3.0,
    TLS 1.0, TLS 1.1) and optionally enables/disables TLS 1.2 based on the
    `$MakeSecure` variable.

    - $true  = secure remediation (disable insecure protocols, enable TLS 1.2)
    - $false = vulnerability creation (enable old protocols, disable TLS 1.2)

.NOTES
    Author        : Jordan Calvert
    Last Modified : 2025-11-25
    Version       : 2.0

.TESTED ON
    Windows Server 2019/2022/2025
    Windows 10 / Windows 11
#>

Write-Host "`n=== Protocol Toggle Script Starting ===" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Mode Selection
# -------------------------------------------------------------
# TRUE  = secure
# FALSE = insecure (vulnerability creation)
$MakeSecure = $true     # <-- Change this for lab mode

# -------------------------------------------------------------
# 2. Admin Check
# -------------------------------------------------------------
function Test-IsAdmin {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "`n✗ Access Denied. Run this script as Administrator.`n"
    exit 1
}

# -------------------------------------------------------------
# 3. Helper Function to Toggle Protocols
# -------------------------------------------------------------
function Set-ProtocolState {
    param (
        [string]$Protocol,
        [bool]$Enable
    )

    $ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
    $ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client"

    # Ensure key paths exist
    New-Item -Path $ServerPath -Force | Out-Null
    New-Item -Path $ClientPath -Force | Out-Null

    if ($Enable) {
        # Vulnerability Creation: Turn protocol ON
        Set-ItemProperty -Path $ServerPath -Name "Enabled" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ServerPath -Name "DisabledByDefault" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ClientPath -Name "Enabled" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ClientPath -Name "DisabledByDefault" -Value 0 -Type DWord -Force

        Write-Host "  [+] $Protocol ENABLED (insecure)" -ForegroundColor Red
    }
    else {
        # Remediation: Turn protocol OFF
        Set-ItemProperty -Path $ServerPath -Name "Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ServerPath -Name "DisabledByDefault" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ClientPath -Name "Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ClientPath -Name "DisabledByDefault" -Value 1 -Type DWord -Force

        Write-Host "  [+] $Protocol DISABLED (secure)" -ForegroundColor Green
    }
}

# -------------------------------------------------------------
# 4. Apply Settings
# -------------------------------------------------------------
Write-Host "`n[*] Applying SSL/TLS protocol configuration..." -ForegroundColor Yellow

$LegacyProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
$ModernProtocols = @("TLS 1.2")

# Legacy Protocols (insecure)
foreach ($proto in $LegacyProtocols) {
    Set-ProtocolState -Protocol $proto -Enable:(-not $MakeSecure)
}

# TLS 1.2 (secure modern protocol)
foreach ($proto in $ModernProtocols) {
    Set-ProtocolState -Protocol $proto -Enable:$MakeSecure
}

# -------------------------------------------------------------
# 5. Completion
# -------------------------------------------------------------
Write-Host "`n=== Protocol Toggle Complete ===" -ForegroundColor Cyan
Write-Host "A system reboot is required for settings to take effect.`n" -ForegroundColor Cyan
