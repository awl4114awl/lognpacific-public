<#
.SYNOPSIS
    Toggles Windows TLS/SSL cipher suites between secure and insecure sets.

.DESCRIPTION
    This script sets the system's SSL/TLS cipher suite order to one of two modes:
      • Secure (production-safe)
      • Insecure (vulnerability-creation for Cyber Range labs)

    Cipher suite configuration is applied using Group Policy registry keys.
    A reboot is required for changes to take effect.

.NOTES
    Author        : Jordan Calvert
    Last Modified : 2025-11-25
    Tested On     : Windows Server 2019, Windows 10, Windows 11
#>

Write-Host "`n=== Cipher Suite Toggle Starting ===" -ForegroundColor Cyan

# -------------------------------------------------------------
# 1. Toggle Mode
# -------------------------------------------------------------
# true  = secure (remediation)
# false = insecure (vulnerability creation)
$SecureEnvironment = $false     # <-- CHANGE as needed

# -------------------------------------------------------------
# 2. Cipher Suite Definitions
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

$InsecureCipherSuites = @(
    $SecureCipherSuites.Split(','),
    # Insecure, export, weak, deprecated
    "TLS_RSA_WITH_DES_CBC_SHA","TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA","TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA","TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5","TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "SSL_RSA_WITH_DES_CBC_SHA","SSL_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_RC4_128_SHA","SSL_RSA_WITH_RC4_128_MD5",
    "SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA","SSL_RSA_EXPORT1024_WITH_RC4_56_SHA",
    "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5","SSL_RSA_EXPORT_WITH_RC4_40_MD5"
) -join ','

# -------------------------------------------------------------
# 3. Determine mode
# -------------------------------------------------------------
if ($SecureEnvironment) {
    $SelectedCipherSuites = $SecureCipherSuites
    Write-Host "[*] Configuring SECURE cipher suite order..." -ForegroundColor Yellow
}
else {
    $SelectedCipherSuites = $InsecureCipherSuites
    Write-Host "[*] Configuring INSECURE cipher suite order (lab vulnerability)..." -ForegroundColor Red
}

# -------------------------------------------------------------
# 4. Registry Paths
# -------------------------------------------------------------
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# -------------------------------------------------------------
# 5. Apply Cipher Suites
# -------------------------------------------------------------
try {
    Set-ItemProperty -Path $RegPath -Name "Functions" -Value $SelectedCipherSuites -Force
    Set-ItemProperty -Path $RegPath -Name "Enabled"   -Value 1 -Force

    Write-Host "✓ Cipher suites successfully written to policy." -ForegroundColor Green
}
catch {
    Write-Host "✗ Failed to update cipher suites: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# -------------------------------------------------------------
# 6. Verify
# -------------------------------------------------------------
try {
    $Result = (Get-ItemProperty -Path $RegPath -Name "Functions").Functions
    Write-Host "`nCurrent Cipher Suite Order:" -ForegroundColor Cyan
    $Result
}
catch {
    Write-Host "✗ Unable to read back cipher suite configuration." -ForegroundColor Red
}

# -------------------------------------------------------------
# 7. Final Message
# -------------------------------------------------------------
Write-Host "`nA restart is required for cipher suite changes to take effect." -ForegroundColor Cyan
Write-Host "=== Cipher Suite Toggle Complete ===`n" -ForegroundColor Cyan
