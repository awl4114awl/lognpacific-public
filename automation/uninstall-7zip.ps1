<#
.SYNOPSIS
    Uninstalls all detected versions of 7-Zip from the system.

.DESCRIPTION
    Searches the Windows registry for 7-Zip uninstall entries and executes the
    corresponding uninstaller silently. Works for both x64 and x86 installs.
    Must be run as Administrator.

.AUTHOR
    Jordan Calvert
    Date: 2025-11-05
#>

Write-Host "Searching for 7-Zip installations..." -ForegroundColor Cyan

# Define both possible registry paths
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$found = $false

foreach ($path in $registryPaths) {
    Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
        $displayName = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
        if ($displayName -and $displayName -match "7-Zip") {
            $found = $true
            $uninstallString = (Get-ItemProperty $_.PSPath).UninstallString
            Write-Host "Found: $displayName" -ForegroundColor Yellow
            Write-Host "Uninstalling..."
            
            # If the uninstall string includes msiexec, run it silently
            if ($uninstallString -match "msiexec") {
                Start-Process "cmd.exe" "/c $uninstallString /qn /norestart" -Wait
            }
            else {
                # Otherwise, call the EXE directly with silent parameters
                Start-Process "cmd.exe" "/c `"$uninstallString`" /S" -Wait
            }
        }
    }
}

if ($found) {
    Write-Host "7-Zip has been uninstalled. Reboot recommended." -ForegroundColor Green
} else {
    Write-Host "No 7-Zip installations were found." -ForegroundColor Red
}
