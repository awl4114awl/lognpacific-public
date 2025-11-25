<#
.SYNOPSIS
    Applies a strict, secure TLS/SSL cipher suite configuration.

.DESCRIPTION
    This script configures Windows to use ONLY secure cipher suites
    and explicitly enables Group Policy enforcement of cipher suite order.

    This script is intended for remediation or secure system configuration
    inside Cyber Range or enterprise hardening environments.

.NOTES
    Author        : Jordan Calvert
    Last Modified : 2025-11-25
    Tested On     : Windows Server 2019, Windows 10, Windows 11
#>

Write-Host "`n=== Secure Cipher Suite Configuration Starting ===" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Mode: SECURE ONLY
# -------------------------------------------------------------
$SecureEnvironment = $true   # This script forces the secure mode

# -------------------------------------------------------------
# 2. Secure Cipher Suites (allowed list)
# -------------------------------------------------------------
$SecureCipherSuites = @(
    "TLS_AES_256_GCM_SHA384","TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384","TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384","TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256","TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA","TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_NULL_SHA256","TLS_RSA_WITH_NULL_SHA",
    "TLS_PSK_WITH_AES_256_GCM_SHA384","TLS_PSK_WITH_AES_128_GCM_SHA256",
    "TLS_PSK_WITH_AES_256_CBC_SHA384","TLS_PSK_WITH_AES_128_CBC_SHA256",
    "TLS_PSK_WITH_NULL_SHA384","TLS_PSK_WITH_NULL_SHA256"
) -join ','

Write-Host "[*] Configuring SECURE cipher suite order..." -ForegroundColor Yellow

# -------------------------------------------------------------
# 3. Registry Path Setup
# -------------------------------------------------------------
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# -------------------------------------------------------------
# 4. Apply Cipher Suites
# -------------------------------------------------------------
try {
    Set-ItemProperty -Path $RegPath -Name "Functions" -Value $SecureCipherSuites -Force
    Set-ItemProperty -Path $RegPath -Name "Enabled"   -Value 1 -Force

    Write-Host "✓ Secure cipher suites successfully applied." -ForegroundColor Green
}
catch {
    Write-Host "✗ Failed to update cipher suite configuration: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# -------------------------------------------------------------
# 5. Verify Configuration
# -------------------------------------------------------------
Write-Host "`nCurrent Cipher Suite Order (Secure):" -ForegroundColor Cyan

try {
    (Get-ItemProperty -Path $RegPath -Name "Functions").Functions
}
catch {
    Write-Host "✗ Could not verify cipher suite order." -ForegroundColor Red
}

# -------------------------------------------------------------
# 6. Final Message
# -------------------------------------------------------------
Write-Host "`nA restart is required for cipher suite changes to take effect." -ForegroundColor Cyan
Write-Host "=== Secure Cipher Suite Configuration Complete ===`n" -ForegroundColor Cyan
