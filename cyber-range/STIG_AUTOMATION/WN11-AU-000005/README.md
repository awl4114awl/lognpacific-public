# Step By Step STIG Automation for STIG ID: WN11-AC-000005

## ℹ️ Overview

This lab was carried out in The Cyber Range, an Azure-hosted enterprise environment where I replicate real-world detection, investigation, and remediation workflows. In this scenario, I focused on STIG automation using PowerShell combined with Tenable authenticated scanning.

To create a realistic compliance and remediation exercise, I deliberately disabled the Windows Firewall on a Windows 11 Pro virtual machine. I then worked through a structured STIG implementation lifecycle that mirrors how compliance controls are identified, validated, and enforced in an enterprise environment.

The workflow included:
- Scanning the VM with a Windows 11 STIG Audit Policy
- Reviewing scan results and selecting a failed STIG (WN11-AC-000005)
- Implementing the STIG manually and validating success
- Reverting the fix to confirm failure
- Automating the remediation using PowerShell
- Re-scanning to confirm successful enforcement

Through this lab, I demonstrate my ability to interpret STIG requirements, manually validate security controls, translate policy guidance into registry-level configuration changes, and automate compliance enforcement using PowerShell.

---

## 📓 Lab Workflow

### 1️⃣ Provision the Windows 11 Virtual Machine

I provisioned a Windows 11 Pro virtual machine in Microsoft Azure using the Cyber Range infrastructure.

| Component | Details |
|---------|--------|
| VM Name | win11-STIG-vm |
| OS Image | Windows 11 25H2 Pro |
| Region | East US 2 |
| VM Size | Standard DS1 v2 (1 vCPU, 3.5 GiB RAM) |
| Security Type | Trusted Launch (Secure Boot + vTPM Enabled) |
| Network | Cyber-Range-VNet / Cyber-Range-Subnet |
| Public IP | 135.119.159.49 |
| Private IP | 10.0.0.100 |
| Disk Encryption | Disabled |
| Auto-Shutdown | Not Enabled |
| Extensions | AzurePolicyforWindows |

---

### 2️⃣ Disable the Windows Firewall

To simulate a misconfigured system commonly encountered in real environments, I disabled the Windows Firewall on the virtual machine.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-30 114859.png" width="750">
</p>

---

### 3️⃣ Create an Advanced Network Scan and Run a Baseline Scan

I logged into Tenable Vulnerability Management and created a new scan using a User Defined template scan.

- Scanner: LOCAL-SCAN-ENGINE-01
- Target: VM private IP address (10.0.0.100)

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 095347.png" width="750">
</p>

I configured the scan with Windows credentials for authenticated access and added Compliance Checks for DISA Windows 11 STIG v2r4.

To ensure the scan focused only on STIG compliance and completed quickly:

- All vulnerability plugins were disabled
- Only Policy Compliance → Windows Compliance Checks were enabled

I then ran the initial baseline scan.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-30 120951.png" width="750">
</p>

<a href="https://drive.google.com/file/d/1imQba_m9yZ3OuJZPvsoxVytgeC9GnwjN/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_1_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 4️⃣ Investigate Scan Results and Identify the STIG

After reviewing the scan results, I identified a failed STIG: WN11-AC-000005.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-30 133109.png" width="750">
</p>

According to stigaview.com, Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Credential validation records events related to validation tests on credentials for a user account logon.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-30 133629.png" width="750">
</p>

---

### 5️⃣ Manually Apply the STIG and Verify the Fix

To manually apply STIG WN11-AU-000005, Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >> System Audit Policies >> Account Logon >> "Audit Credential Validation" with "Failure" selected.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-30 134333.png" width="750">
</p>

After applying the change, I restarted the VM and ran the scan again to validate the fix.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 054624.png" width="750">
  <img src="screenshots/Screenshot 2025-12-31 054720.png" width="750">
</p>


<a href="https://drive.google.com/file/d/1de8ahddeMQmEHoZgHew9EjsnG4eLvpiP/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_2_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

## 6️⃣ Revert the Fix and Confirm Failure

To confirm that the STIG compliance result for WN11-AU-000005 was directly tied to the Advanced Audit Policy configuration for credential validation events, I reverted the system back to a non-compliant state by removing the local audit policy configuration and validating the resulting failure.

During initial revert testing, I disabled auditing for the Credential Validation subcategory using AuditPol. While this temporarily modified the effective audit policy, the “Audit Credential Validation” setting continued to appear as configured within the Local Group Policy Editor. This behavior indicated that the audit setting was being enforced through the locally applied Advanced Audit Policy configuration rather than solely through the current effective audit state.

To fully revert the control in the same manner as deselecting “Configure the following audit events” in Local Group Policy, I removed the local Advanced Audit Policy configuration file used by the Local Group Policy Object (LGPO). The Advanced Audit Policy configuration is stored locally at the following path:

`C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv`

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 061828.png" width="750">
</p>

I deleted the file to remove the locally enforced audit configuration and return the policy to a Not Configured state:

```PowerShell
$AuditCsv = "$env:windir\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv"
if (Test-Path $AuditCsv) {
    Remove-Item $AuditCsv -Force
}
```

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 062007.png" width="750">
</p>

Removing the LGPO-backed Advanced Audit Policy configuration alone was insufficient to clear the effective audit state for Credential Validation. 

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 063028.png" width="750">
</p>

As a result, explicit disabling via AuditPol was required to fully revert the system to a non-compliant state.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 063256.png" width="750">
</p>

The output confirmed that auditing for the Credential Validation subcategory was no longer enabled after explicitly disabling the effective audit policy, placing the system back into a non-compliant state relative to the WN11-AU-000005 requirement.

I then re-ran the authenticated STIG compliance scan. As expected, WN11-AU-000005 returned to a failed state, confirming that the control’s compliance result is dependent on the effective Advanced Audit Policy state for credential validation events rather than solely on the Local Group Policy configuration being set to Not Configured.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 065205.png" width="750">
  <img src="screenshots/Screenshot 2025-12-31 065249.png" width="750">
</p>

<a href="https://drive.google.com/file/d/131my_koOIHMqhzXMu18x_49Ra4IJBrtT/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_3_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 7️⃣ Generate and Apply the PowerShell Remediation

After validating the manual fix and confirming the revert behavior, I translated the STIG requirements for WN11-AU-000005 into an automated PowerShell remediation script.

This control is enforced through Advanced Audit Policy configuration under the Account Logon category, specifically the “Credential Validation” audit subcategory. Because compliance is evaluated based on the effective audit policy state rather than a single registry value or Local Group Policy setting, the remediation script was designed to configure auditing programmatically using supported Windows audit policy utilities instead of relying on the Local Group Policy Editor.

The script was designed to:

- Enable STIG-compliant auditing for credential validation events
- Enforce the “Failure” audit setting for the “Credential Validation” subcategory
- Apply the configuration using auditpol to ensure the audit policy is updated
- Verify the effective audit policy state after changes are applied
- Provide repeatable remediation and validation during STIG compliance testing
- Support quick rollback and re-application to validate scan results 


---

### To test the automation:

- I logged back into the virtual machine  
- Downloaded the PowerShell remediation script from my GitHub repository  
- Ran the script in an elevated PowerShell session


Before remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 081927.png" width="750">
</p>

After remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 082423.png" width="750">
</p>

---

### 8️⃣ Confirm STIG Compliance via Re-Scan

After applying the PowerShell script, I ran another authenticated compliance scan in Tenable.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 092805.png" width="750">
  <img src="screenshots/Screenshot 2025-12-31 092830.png" width="750">
</p>

The scan confirmed that STIG WN11-AC-000005 was successfully applied and passed, demonstrating that the automated remediation was effective.

<a href="https://drive.google.com/file/d/1uC6yiqQA5wnuEJMok3NLdSwcmzBwHaWj/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_4_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>

<br>

---

### 9️⃣ Conclusion

This lab demonstrates a complete STIG suggesting, validation, and automation lifecycle. By manually implementing, reverting, and then automating the STIG control, I validated both my understanding of DISA STIG requirements and my ability to enforce them programmatically.


This workflow reflects real-world compliance operations where security controls must be validated manually, automated reliably, and continuously verified through authenticated scanning.

