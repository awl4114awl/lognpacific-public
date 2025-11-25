<#
.SYNOPSIS
    Removes Mozilla Firefox silently as part of a remediation workflow.

.DESCRIPTION
    This script checks for the Firefox uninstall helper and runs it silently
    using Start-Process instead of Invoke-Expression (which is insecure).
#>

Write-Host "`n=== Firefox Uninstallation Starting ===" -ForegroundColor Cyan

# Path to Firefox uninstall helper
$UninstallHelperPath = "C:\Program Files\Mozilla Firefox\uninstall\helper.exe"

# Verify the uninstaller exists
if (Test-Path -Path $UninstallHelperPath) {
    Write-Host "[*] Found uninstall helper. Running silent uninstall..." -ForegroundColor Yellow

    try {
        Start-Process -FilePath $UninstallHelperPath -ArgumentList "/S" -Wait -NoNewWindow
        Write-Host "[+] Firefox uninstalled successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "[-] Failed to uninstall Firefox: $($_.Exception.Message)"
    }
}
else {
    Write-Host "[-] Firefox uninstall helper not found at: $UninstallHelperPath" -ForegroundColor Red
}

Write-Host "`n=== Firefox Uninstallation Complete ===`n" -ForegroundColor Cyan
