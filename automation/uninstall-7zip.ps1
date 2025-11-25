<#
.SYNOPSIS
    Uninstalls all detected versions of 7-Zip from the system.

.DESCRIPTION
    Searches both 32-bit and 64-bit uninstall registry locations for any
    7-Zip installation entries. Executes uninstallation silently using MSI
    or EXE uninstallers depending on the stored uninstall string.

.NOTES
    Author        : Jordan Calvert
    Last Modified : 2025-11-25
    Version       : 1.1

    Must be run with Administrator privileges.
#>

Write-Host "`n=== 7-Zip Uninstall Script Starting ===" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Registry paths to scan
# -------------------------------------------------------------
$RegistryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$Found = $false

# -------------------------------------------------------------
# 2. Function to run an uninstall command safely
# -------------------------------------------------------------
function Invoke-Uninstall {
    param (
        [string]$UninstallString
    )

    try {
        # MSI-based uninstall
        if ($UninstallString -match "msiexec") {
            Write-Host "  [+] Executing MSI uninstall..." -ForegroundColor Yellow
            Start-Process "msiexec.exe" "$UninstallString /qn /norestart" -Wait
        }
        else {
            # Clean quoted paths (sometimes uninstall strings contain quotes)
            $CleanString = $UninstallString.Trim('"')

            Write-Host "  [+] Executing EXE uninstall..." -ForegroundColor Yellow
            Start-Process $CleanString "/S" -Wait
        }

        Write-Host "  ✓ Uninstall completed." -ForegroundColor Green
    }
    catch {
        Write-Host "  ✗ Failed to uninstall: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# -------------------------------------------------------------
# 3. Search registry and uninstall all detected versions
# -------------------------------------------------------------
foreach ($Path in $RegistryPaths) {
    Write-Host "`nScanning: $Path" -ForegroundColor Gray

    $Entries = Get-ChildItem $Path -ErrorAction SilentlyContinue

    foreach ($Entry in $Entries) {
        try {
            $Props = Get-ItemProperty $Entry.PSPath -ErrorAction Stop
        }
        catch {
            continue
        }

        if ($Props.DisplayName -and $Props.DisplayName -match "7-Zip") {

            $Found = $true
            Write-Host "`nFound Installation: $($Props.DisplayName)" -ForegroundColor Yellow

            if ($Props.UninstallString) {
                Write-Host "  [+] Uninstall string detected."
                Invoke-Uninstall -UninstallString $Props.UninstallString
            }
            else {
                Write-Host "  ✗ No uninstall string found — cannot remove this entry." -ForegroundColor Red
            }
        }
    }
}

# -------------------------------------------------------------
# 4. Final Output
# -------------------------------------------------------------
if ($Found) {
    Write-Host "`n✓ All detected 7-Zip installations processed. A reboot is recommended." -ForegroundColor Green
}
else {
    Write-Host "`nℹ No 7-Zip installations were found on this system." -ForegroundColor Gray
}

Write-Host "`n=== 7-Zip Uninstall Script Complete ===`n" -ForegroundColor Cyan
