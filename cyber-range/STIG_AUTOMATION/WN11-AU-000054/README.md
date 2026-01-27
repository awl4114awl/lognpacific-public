# Step By Step STIG Automation for STIG ID: WN11-AU-000054

## ⓘ Overview

This lab was carried out in The Cyber Range, an Azure-hosted enterprise environment where I replicate real-world detection, investigation, and remediation workflows. In this scenario, I focused on STIG automation using PowerShell combined with Tenable authenticated scanning.

To create a realistic compliance and remediation exercise, I deliberately disabled the Windows Firewall on a Windows 11 Pro virtual machine. I then worked through a structured STIG implementation lifecycle that mirrors how compliance controls are identified, validated, and enforced in an enterprise environment.

The workflow included:
- Scanning the VM with a Windows 11 STIG Audit Policy
- Reviewing scan results and selecting a failed STIG (WN11-AU-000054)
- Implementing the STIG manually and validating success
- Reverting the fix to confirm failure
- Automating the remediation using PowerShell
- Re-scanning to confirm successful enforcement

Through this lab, I demonstrate my ability to interpret STIG requirements, manually validate security controls, translate policy guidance into registry-level configuration changes, and automate compliance enforcement using PowerShell.

---

### 1. Provision the Windows 11 Virtual Machine

I provisioned a Windows 11 Pro virtual machine in Microsoft Azure using the Cyber Range infrastructure.

| Component | Details |
|---------|--------|
| VM Name | win11-STIG-vm |
| OS Image | Windows 11 25H2 Pro |
| Region | East US 2 |
| VM Size | Standard DS1 v2 (1 vCPU, 3.5 GiB RAM) |
| Security Type | Trusted Launch (Secure Boot + vTPM Enabled) |
| Network | Cyber-Range-VNet / Cyber-Range-Subnet |
| Public IP | 172.172.41.111 |
| Private IP | 10.0.0.144 |
| Disk Encryption | Disabled |
| Auto-Shutdown | Not Enabled |
| Extensions | AzurePolicyforWindows |

---

### 2. Disable the Windows Firewall

To simulate a misconfigured system commonly encountered in real environments, I disabled the Windows Firewall on the virtual machine.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 095159.png" width="750">
</p>

---

### 3. Create an Advanced Network Scan and Run a Baseline Scan

I logged into Tenable Vulnerability Management and created a new scan using a User Defined template scan.

- Scanner: LOCAL-SCAN-ENGINE-01
- Target: VM private IP address (10.0.0.144)

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 095347.png" width="750">
</p>

I configured the scan with Windows credentials for authenticated access and added Compliance Checks for DISA Windows 11 STIG v2r4.

To ensure the scan focused only on STIG compliance and completed quickly:

- All vulnerability plugins were disabled
- Only Policy Compliance → Windows Compliance Checks were enabled

I then ran the initial baseline scan.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 095720.png" width="750">
</p>

<a href="https://drive.google.com/file/d/11PPyU5_PsuZdRfkBq6yPRothnxwh2fBM/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_1_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 4. Investigate Scan Results and Identify the STIG

After reviewing the scan results, I identified a failed STIG: WN11-AU-000054.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 114919.png" width="750">
</p>

According to stigaview.com, Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Account Lockout events can be used to identify potentially malicious logon attempts.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 102737.png" width="750">
</p>

---

### 5. Manually Apply the STIG and Verify the Fix

To manually apply STIG WN11-AU-000054, Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Account Lockout" with "Failure" selected.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 120204.png" width="750">
</p>

After applying the change, I restarted the VM and ran the scan again to validate the fix.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 130303.png" width="750">
  <img src="screenshots/Screenshot 2025-12-29 130341.png" width="750">
</p>


<a href="https://drive.google.com/file/d/12A5zeiJlkiGzbmReid2ozZIdhEwupyAw/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_2_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

## 6. Revert the Fix and Confirm Failure

To confirm that the STIG compliance result for WN11-AU-000054 was directly tied to the Advanced Audit Policy configuration for account lockout events, I reverted the system back to a non-compliant state by removing the local policy configuration and validating the resulting failure.

During initial revert testing, I disabled failure auditing using AuditPol. Although this modified the effective audit policy temporarily, the “Audit Account Lockout” setting continued to appear as configured in the Local Group Policy Editor. This behavior indicated that the audit setting was being enforced through the local policy-backed Advanced Audit Policy configuration rather than solely through the current effective audit state.

To revert the control in the same way as deselecting “Configure the following audit events” in Local Group Policy, I removed the local Advanced Audit Policy configuration file used by the Local Group Policy Object (LGPO). The Advanced Audit Policy configuration is stored locally in the following file:

`C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv`

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 142909.png" width="750">
</p>

I deleted the file so the system would remove the locally configured audit policy and return the setting to “Not Configured”

```PowerShell
$AuditCsv = "$env:windir\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv"
if (Test-Path $AuditCsv) {
Remove-Item $AuditCsv -Force
}
```

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 143319.png" width="750">
</p>

After updating policy, I verified the effective audit configuration for the relevant subcategory

```powershell
auditpol /get /subcategory:"Account Lockout"
```

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 143502.png" width="750">
  <img src="screenshots/Screenshot 2025-12-29 143913.png" width="750">  
</p>

The output confirmed that failure auditing was no longer enabled for the “Account Lockout” subcategory, placing the system back into a non-compliant state relative to the WN11-AU-000054 requirement.

I then re-ran the authenticated STIG compliance scan. As expected, STIG WN11-AU-000054 returned to a failed state, confirming that the control’s compliance result is directly dependent on the Advanced Audit Policy configuration for “Audit Account Lockout” and that returning the policy to an unconfigured state results in non-compliance.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 165014.png" width="750">
  <img src="screenshots/Screenshot 2025-12-29 165201.png" width="750">  
</p>

<a href="https://drive.google.com/file/d/17Xsvv5lOpZSOpPHugXbOOkRnqVQRzT5w/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_3_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 7. Generate and Apply the PowerShell Remediation

After validating the manual fix and confirming the revert behavior, I translated the STIG requirements for WN11-AU-000054 into an automated PowerShell remediation script.

This control is enforced through Advanced Audit Policy configuration under the Logon/Logoff category, specifically the “Account Lockout” audit subcategory. Because the compliance requirement is evaluated based on the effective audit policy state (rather than a single registry value), the remediation script was designed to configure auditing programmatically using supported Windows audit policy utilities instead of relying on the Local Group Policy Editor.

The script was designed to:


- Enable STIG-compliant auditing for Logon/Logoff account lockout events
- Enforce the required “Failure” audit setting for the “Account Lockout” subcategory
- Apply the configuration using auditpol to ensure the effective audit policy is updated immediately
- Verify the effective audit policy state after changes are applied
- Provide repeatable remediation and validation during STIG compliance testing
- Support quick rollback and re-application to validate scan results across multiple test cycles

---

### To test the automation:

- I logged back into the virtual machine  
- Downloaded the PowerShell remediation script from my GitHub repository  
- Ran the script in an elevated PowerShell session

Before remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-30 080335.png" width="750">
</p>

After remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-30 082135.png" width="750">
</p>

I executed the remediation script, which enabled failure auditing for “Account Lockout” and then re-queried the effective audit policy to confirm that the required setting was applied. The audit policy reflected “Failure” auditing enabled for the subcategory, restoring STIG compliance for WN11-AU-000054.

---

### 8. Confirm STIG Compliance via Re-Scan

After applying the PowerShell script, I ran another authenticated compliance scan in Tenable.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-30 083404.png" width="750">
  <img src="screenshots/Screenshot 2025-12-30 101855.png" width="750">
  <img src="screenshots/Screenshot 2025-12-30 101927.png" width="750">
</p>

The scan confirmed that STIG WN11-AU-000054 was successfully applied and passed, demonstrating that the automated remediation was effective.

<a href="https://drive.google.com/file/d/1m3yduuS6bMdLf6J-DNSlgBC8Fvp4ii1z/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_4_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>

<br>

---

### 9. Conclusion

This lab demonstrates a complete STIG suggesting, validation, and automation lifecycle. By manually implementing, reverting, and then automating the STIG control, I validated both my understanding of DISA STIG requirements and my ability to enforce them programmatically.
