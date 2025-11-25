<#
.SYNOPSIS
    Adds or removes the Guest account from the local Administrators group.

.DESCRIPTION
    This script toggles whether the built-in Guest account is a member
    of the local Administrators group. It can be used for both:
      • vulnerability creation (add Guest → insecure)
      • remediation (remove Guest → secure)

    A reboot is NOT required for this change to take effect.

.NOTES
    Author        : Jordan Calvert
    Last Modified : 2025-11-25
    Version       : 1.1

.TESTED ON
    Windows Server 2025 Datacenter
    Windows Server 2019/2022
    Windows 10 / Windows 11
#>

Write-Host "`n=== Guest Local Administrators Group Toggle Starting ===" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Mode selection
# -------------------------------------------------------------
# True  = ADD Guest → insecure (vulnerability creation)
# False = REMOVE Guest → secure (remediation)
$AddGuestToAdminGroup = $False   # <-- Change as needed

# -------------------------------------------------------------
# 2. Variables
# -------------------------------------------------------------
$LocalAdminGroup = "Administrators"
$GuestAccount     = "Guest"

# -------------------------------------------------------------
# 3. Check group membership safely
# -------------------------------------------------------------
function Test-GuestInAdminGroup {
    try {
        $result = Get-LocalGroupMember -Group $LocalAdminGroup -Member $GuestAccount -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# -------------------------------------------------------------
# 4. ADD Guest to Administrators (vulnerability creation)
# -------------------------------------------------------------
function Add-GuestToAdminGroup {
    if (-not (Test-GuestInAdminGroup)) {
        Write-Host "[*] Adding Guest to Administrators group..." -ForegroundColor Yellow
        try {
            Add-LocalGroupMember -Group $LocalAdminGroup -Member $GuestAccount -ErrorAction Stop
            Write-Host "✓ Guest added to Administrators group (INSECURE)." -ForegroundColor Red
        }
        catch {
            Write-Host "✗ Failed to add Guest to Administrators group: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "ℹ Guest is already in Administrators group." -ForegroundColor Gray
    }
}

# -------------------------------------------------------------
# 5. REMOVE Guest from Administrators (remediation)
# -------------------------------------------------------------
function Remove-GuestFromAdminGroup {
    if (Test-GuestInAdminGroup) {
        Write-Host "[*] Removing Guest from Administrators group..." -ForegroundColor Yellow
        try {
            Remove-LocalGroupMember -Group $LocalAdminGroup -Member $GuestAccount -ErrorAction Stop
            Write-Host "✓ Guest removed from Administrators group (SECURE)." -ForegroundColor Green
        }
        catch {
            Write-Host "✗ Failed to remove Guest from Administrators group: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "ℹ Guest is not a member of Administrators group." -ForegroundColor Gray
    }
}

# -------------------------------------------------------------
# 6. Execute based on user intent
# -------------------------------------------------------------
if ($AddGuestToAdminGroup) {
    Add-GuestToAdminGroup
}
else {
    Remove-GuestFromAdminGroup
}

Write-Host "`n=== Guest Local Administrators Group Toggle Complete ===`n" -ForegroundColor Cyan
