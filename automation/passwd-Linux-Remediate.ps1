<#
.SYNOPSIS
    Remediates insecure Linux file permissions created for lab exercises.

.DESCRIPTION
    This script connects to a Linux host over SSH and restores secure
    permissions for /etc/shadow and /etc/passwd.

    • /etc/shadow → 400 (root read only)
    • /etc/passwd → 644 (root writable, world readable)

    This script is the corrective counterpart to the vulnerability
    introduction script "passwd-Linux-Create-Vulnerability.ps1".
#>

# --- Configuration ---
$LinuxHost = "192.168.1.50"       # <-- Update to your Linux VM
$Username  = "labuser"            # <-- Update as needed
$Password  = "Password123!"       # <-- Same creds used for creation script

# Convert credentials
$SecurePass = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred       = New-Object System.Management.Automation.PSCredential ($Username, $SecurePass)

Write-Host "`n=== Remediating Linux Account File Permissions ===" -ForegroundColor Cyan

# Commands to fix the insecure permissions
$Commands = @(
    "sudo chmod 400 /etc/shadow",
    "sudo chmod 644 /etc/passwd"
)

try {
    foreach ($cmd in $Commands) {
        Write-Host "[*] Executing remediation: $cmd" -ForegroundColor Yellow
        $result = ssh $Cred@$LinuxHost $cmd
        Write-Host $result
    }

    Write-Host "`n[+] Permissions successfully restored:" -ForegroundColor Green
    Write-Host "    /etc/shadow → 400" -ForegroundColor Green
    Write-Host "    /etc/passwd → 644" -ForegroundColor Green
}
catch {
    Write-Error "Failed to remediate permissions: $($_.Exception.Message)"
}

Write-Host "`n=== Remediation Complete ===`n"
