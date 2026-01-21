# 🗒️ Step By Step STIG Automation for STIG ID: WN11-CC-000252

## ℹ️ Overview

This lab was carried out in The Cyber Range, an Azure-hosted enterprise environment where I replicate real-world detection, investigation, and remediation workflows. In this scenario, I focused on STIG automation using PowerShell combined with Tenable authenticated scanning.

To create a realistic compliance and remediation exercise, I deliberately disabled the Windows Firewall on a Windows 11 Pro virtual machine. I then worked through a structured STIG implementation lifecycle that mirrors how compliance controls are identified, validated, and enforced in an enterprise environment.

The workflow included:

- Scanning the VM with a Windows 11 STIG Audit Policy  
- Reviewing scan results and selecting a failed STIG (WN11-CC-000252)  
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
| Public IP | 172.177.49.11 |
| Private IP | 10.0.0.124 |
| Disk Encryption | Disabled |
| Auto-Shutdown | Not Enabled |
| Extensions | AzurePolicyforWindows |

---

### 2️⃣ Disable the Windows Firewall

To simulate a misconfigured system commonly encountered in real environments, I disabled the Windows Firewall on the virtual machine.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 081759.png" width="750">
</p>

---

### 3️⃣ Create an Advanced Network Scan and Run a Baseline Scan

I logged into Tenable Vulnerability Management and created a new scan using a User Defined template scan.

**Scanner:** LOCAL-SCAN-ENGINE-01  
**Target:** VM private IP address (10.0.0.124)

<p align="left">
  <img src="screenshots/Screenshot 2025-12-29 095347.png" width="750">
</p>

I configured the scan with Windows credentials for authenticated access and added Compliance Checks for DISA Windows 11 STIG v2r4.

To ensure the scan focused only on STIG compliance and completed quickly:

- All vulnerability plugins were disabled  
- Only Policy Compliance → Windows Compliance Checks were enabled  

I then ran the initial baseline scan.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 082248.png" width="750">
</p>

<a href="https://drive.google.com/file/d/1YbGurSVpyJ0AXmRRwcTXX1j3S3lrEPG8/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_1_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 4️⃣ Investigate Scan Results and Identify the STIG

After reviewing the scan results, I identified a failed STIG: WN11-CC-000252.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 101423.png" width="750">
</p>

According to stigaview.com, Windows Game Recording and Broadcasting is intended for use with games; however, it could potentially record screen shots of other applications and expose sensitive data. Disabling the feature will prevent this from occurring.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 101528.png" width="750">
</p>

---

### 5️⃣ Manually Apply the STIG and Verify the Fix

To manually apply STIG WN11-CC-000252, Configure the policy value for:

**Computer Configuration >> Administrative Templates >> Windows Components >> Windows Game Recording and Broadcasting >> "Enables or disables Windows Game Recording and Broadcasting"**  
to **"Disabled"**.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 114258.png" width="750">
  <img src="screenshots/Screenshot 2026-01-02 194325.png" width="750">
  <img src="screenshots/Screenshot 2026-01-02 114418.png" width="750">  
</p>

After applying the change, I restarted the VM and ran the scan again to validate the fix.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 121150.png" width="750">
  <img src="screenshots/Screenshot 2026-01-02 121549.png" width="750">
</p>


<a href="https://drive.google.com/file/d/1VYjHVa7U6pDmjDfa_oVYaYbhC6RDY4L_/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_2_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 6️⃣ Revert the Fix and Confirm Failure

To confirm that compliance with WN11-CC-000252 is dependent on policy-backed registry enforcement applied by Local Group Policy, I reverted the system to a non-compliant state by removing the underlying registry value associated with the control.

The “Enables or disables Windows Game Recording and Broadcasting” policy is enforced through the following registry location:

`HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR`

When the policy is set to Disabled, it creates the following value:

`AllowGameDVR (DWORD) = 0`

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 122857.png" width="750">
</p>

To revert the control and return it to a Not Configured state, I removed the policy-backed registry value using PowerShell:

```powershell
Remove-ItemProperty
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
  -Name "AllowGameDVR"
  -ErrorAction SilentlyContinue
````

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 123108.png" width="750">
</p>

Removing this value cleared the Local Group Policy enforcement and restored the system’s default behavior. I verified that the policy now appeared as Not Configured within the Local Group Policy Editor.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 203326.png" width="750">
</p>

After reverting the configuration, I re-ran the authenticated STIG compliance scan. As expected, WN11-CC-000252 returned to a Failed state, confirming that the control’s compliance result is dependent on the presence of the policy-backed registry value.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 124516.png" width="750">
  <img src="screenshots/Screenshot 2026-01-02 124547.png" width="750">
</p>

<a href="https://drive.google.com/file/d/12Ap4sM_dEIafuUyBwJFKhbR4w2fsLUlk/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_3_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 7️⃣ Generate and Apply the PowerShell Remediation

After validating the manual configuration and confirming the revert behavior, I translated the STIG requirements for WN11-CC-000252 into an automated PowerShell remediation script.

This control is enforced through a policy-backed registry value associated with an Administrative Template. Compliance is evaluated based on whether the required registry value exists and is correctly configured, rather than whether the setting appears explicitly enabled within the Local Group Policy Editor.

The remediation script was designed to:

- Create the required policy registry path if it does not already exist
- Set the AllowGameDVR DWORD value to a STIG-compliant state
- Disable Windows Game Recording and Broadcasting programmatically without relying on the Local Group Policy Editor
- Verify the registry state after remediation
- Support repeatable automation during STIG compliance testing

To test the automation, I performed the following steps:

- Logged back into the virtual machine
- Downloaded the PowerShell remediation script from my GitHub repository
- Executed the script in an elevated PowerShell session

**Before remediation:**

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 125709.png" width="750">
</p>

**After remediation:**

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 125832.png" width="750">
</p>

After executing the remediation script, the required policy-backed registry value was successfully applied, disabling Windows Game Recording and Broadcasting. Although the Local Group Policy Editor continued to display the setting as Not Configured, the registry state confirmed that the control was actively enforced.

I then re-ran the authenticated STIG compliance scan. The scan confirmed that WN11-CC-000252 returned to a Passed state, validating that registry-based enforcement alone is sufficient to satisfy the control requirement.

---

### 8️⃣ Confirm STIG Compliance via Re-Scan

After applying the PowerShell script, I ran another authenticated compliance scan in Tenable.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-02 130848.png" width="750">
  <img src="screenshots/Screenshot 2026-01-02 130939.png" width="750">
</p>

The scan confirmed that STIG WN11-CC-000252 was successfully applied and passed, demonstrating that the automated remediation was effective.

<a href="https://drive.google.com/file/d/1X4AkeXWafvejQdSMMBAEP0kJSz9p-Qgj/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_4_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>

<br>

---

### 9️⃣ Conclusion

This lab demonstrates a complete STIG suggesting, validation, and automation lifecycle. By manually implementing, reverting, and then automating the STIG control, I validated both my understanding of DISA STIG requirements and my ability to enforce them programmatically.


This workflow reflects real-world compliance operations where security controls must be validated manually, automated reliably, and continuously verified through authenticated scanning.

