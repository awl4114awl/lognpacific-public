<#
.SYNOPSIS
    Enables or disables the Guest account on Windows.

.DESCRIPTION
    Allows toggling the built-in Windows Guest account by setting
    $EnableGuestAccount to either $true or $false.

    This script uses the legacy "net user" command for compatibility,
    but provides clean output and idempotent behavior.
#>

Write-Host "`n=== Guest Account Toggle Script Starting ===" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Desired action
# -------------------------------------------------------------
# Set to $true to enable Guest, $false to disable
$EnableGuestAccount = $true     # Change as needed

# Built-in Guest account name
$GuestAccount = "Guest"

# -------------------------------------------------------------
# 2. Function to check current Guest account status
# -------------------------------------------------------------
function Get-GuestAccountStatus {
    $status = net user $GuestAccount 2>$null

    if ($LASTEXITCODE -ne 0) {
        Write-Error "The Guest account could not be queried. It may not exist on this system."
        exit 1
    }

    if ($status -match "Account active\s+Yes") { return $true }
    if ($status -match "Account active\s+No")  { return $false }

    Write-Warning "Unable to determine Guest account status."
    return $null
}

# -------------------------------------------------------------
# 3. Enable or disable Guest account
# -------------------------------------------------------------
function Set-GuestAccountState {
    param (
        [bool]$Enable
    )

    $current = Get-GuestAccountStatus

    if ($current -eq $Enable) {
        if ($Enable) {
            Write-Host "✓ Guest account is already ENABLED." -ForegroundColor Green
        } else {
            Write-Host "✓ Guest account is already DISABLED." -ForegroundColor Green
        }
        return
    }

    if ($Enable) {
        Write-Host "[*] Enabling Guest account..." -ForegroundColor Yellow
        net user $GuestAccount /active:yes | Out-Null
        Write-Host "✓ Guest account enabled." -ForegroundColor Green
    }
    else {
        Write-Host "[*] Disabling Guest account..." -ForegroundColor Yellow
        net user $GuestAccount /active:no | Out-Null
        Write-Host "✓ Guest account disabled." -ForegroundColor Green
    }
}

# -------------------------------------------------------------
# 4. Execute toggle
# -------------------------------------------------------------
Set-GuestAccountState -Enable $EnableGuestAccount

Write-Host "`n=== Guest Account Toggle Complete ===`n" -ForegroundColor Cyan
