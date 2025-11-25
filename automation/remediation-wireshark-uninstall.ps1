<#
.SYNOPSIS
    Remediates the Wireshark vulnerability by uninstalling Wireshark silently.

.DESCRIPTION
    Safely detects and removes Wireshark using its uninstall executable.
    This script is the remediation counterpart to any lab exercise that
    intentionally installs outdated or vulnerable packet capture utilities.

.NOTES
    Author        : Jordan Calvert
    Last Modified : 2025-11-25
    Tested On     : Windows Server 2019 / Windows 10 / Windows 11
#>

Write-Host "`n=== Wireshark Uninstallation (Remediation) Starting ===" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Variables
# -------------------------------------------------------------
$WiresharkDisplayName = "Wireshark 2.2.1 (64-bit)"
$UninstallerPath       = "$env:ProgramFiles\Wireshark\uninstall.exe"
$SilentArgs            = "/S"

# -------------------------------------------------------------
# 2. Detection Function
# -------------------------------------------------------------
function Test-WiresharkInstalled {
    return (Test-Path -Path $UninstallerPath)
}

# -------------------------------------------------------------
# 3. Uninstallation Logic
# -------------------------------------------------------------
function Remove-Wireshark {
    if (Test-WiresharkInstalled) {
        Write-Host "[*] Wireshark installation detected." -ForegroundColor Yellow
        Write-Host "[*] Uninstalling Wireshark silently..." -ForegroundColor Yellow

        try {
            Start-Process -FilePath $UninstallerPath -ArgumentList $SilentArgs -Wait -NoNewWindow
            Write-Host "[+] Wireshark uninstalled successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "[-] Failed to uninstall Wireshark: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "[-] Wireshark does not appear to be installed at:" -ForegroundColor Gray
        Write-Host "    $UninstallerPath" -ForegroundColor Gray
    }
}

# -------------------------------------------------------------
# 4. Execute
# -------------------------------------------------------------
Remove-Wireshark

Write-Host "`n=== Wireshark Remediation Complete ===`n" -ForegroundColor Cyan
