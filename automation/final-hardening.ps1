<#
.SYNOPSIS
    Final Windows Server Hardening Script with 7-Zip Removal

.DESCRIPTION
    Performs final hardening and cleanup by:
      • Uninstalling vulnerable versions of 7-Zip
      • Disabling default accounts
      • Enforcing strong password & lockout policies
      • Enforcing TLS 1.2+ (disabling older protocols)
      • Enabling & configuring Microsoft Defender
      • Enabling detailed audit policies
      • Ensuring Windows Firewall is active

.AUTHOR
    Jordan Calvert
    Date: 2025-11-05
#>

Write-Host "=== Final Hardening Script Starting ===" -ForegroundColor Cyan

# --- 0. Remove vulnerable versions of 7-Zip ---
Write-Host "[0/6] Detecting and removing 7-Zip..." -ForegroundColor Yellow
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
            if ($uninstallString -match "msiexec") {
                Start-Process "cmd.exe" "/c $uninstallString /qn /norestart" -Wait
            }
            else {
                Start-Process "cmd.exe" "/c `"$uninstallString`" /S" -Wait
            }
        }
    }
}
if ($found) {
    Write-Host "7-Zip has been uninstalled. Reboot recommended." -ForegroundColor Green
} else {
    Write-Host "No 7-Zip installations were found." -ForegroundColor Gray
}

# --- 1. Disable default accounts ---
Write-Host "[1/6] Disabling Guest and Administrator accounts..." -ForegroundColor Yellow
net user guest /active:no | Out-Null
net user administrator /active:no | Out-Null

# --- 2. Enforce password and lockout policies ---
Write-Host "[2/6] Configuring password and lockout policies..." -ForegroundColor Yellow
net accounts /minpwlen:14 /maxpwage:30 /lockoutthreshold:3 | Out-Null
Write-Host "Password policy: min length 14, max age 30 days, lockout after 3 attempts."

# --- 3. Enforce TLS 1.2 and disable older protocols ---
Write-Host "[3/6] Enforcing TLS 1.2+ and disabling deprecated protocols..." -ForegroundColor Yellow
$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($proto in $protocols) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $key -Name "DisabledByDefault" -Value 1 -Type DWord -Force
}
$TLS12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
if (-not (Test-Path $TLS12)) { New-Item -Path $TLS12 -Force | Out-Null }
Set-ItemProperty -Path $TLS12 -Name "Enabled" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $TLS12 -Name "DisabledByDefault" -Value 0 -Type DWord -Force
Write-Host "Older SSL/TLS protocols disabled; TLS 1.2 enforced." -ForegroundColor Green

# --- 4. Enable Windows Defender & configure protection ---
Write-Host "[4/6] Enabling Windows Defender features..." -ForegroundColor Yellow
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -SignatureUpdateInterval 4
Start-MpScan -ScanType QuickScan
Write-Host "Windows Defender configured and quick scan started." -ForegroundColor Green

# --- 5. Configure key audit policies ---
Write-Host "[5/6] Setting audit policies for visibility..." -ForegroundColor Yellow
$auditCategories = @(
    "Logon",
    "Account Lockout",
    "Account Management",
    "Policy Change",
    "Privilege Use",
    "System Integrity"
)
foreach ($cat in $auditCategories) {
    auditpol /set /subcategory:"$cat" /success:enable /failure:enable | Out-Null
}
Write-Host "Audit policies applied successfully." -ForegroundColor Green

# --- 6. Ensure Windows Firewall is enabled ---
Write-Host "[6/6] Enabling Windows Firewall on all profiles..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "Firewall enabled for all profiles." -ForegroundColor Green

Write-Host "`nFinal Hardening complete. Reboot recommended for registry changes to apply." -ForegroundColor Cyan
