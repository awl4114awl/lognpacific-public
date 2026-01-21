# 🗒️ Step By Step STIG Automation for STIG ID: WN11-CC-000005

## ℹ️ Overview

This lab was carried out in The Cyber Range, an Azure-hosted enterprise environment where I replicate real-world detection, investigation, and remediation workflows. In this scenario, I focused on STIG automation using PowerShell combined with Tenable authenticated scanning.

To create a realistic compliance and remediation exercise, I deliberately disabled the Windows Firewall on a Windows 11 Pro virtual machine. I then worked through a structured STIG implementation lifecycle that mirrors how compliance controls are identified, validated, and enforced in an enterprise environment.

The workflow included:
- Scanning the VM with a Windows 11 STIG Audit Policy
- Reviewing scan results and selecting a failed STIG (WN11-CC-000005)
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
| Public IP | 172.177.62.179 |
| Private IP | 10.0.0.140 |
| Disk Encryption | Disabled |
| Auto-Shutdown | Not Enabled |
| Extensions | AzurePolicyforWindows |

---

### 2️⃣ Disable the Windows Firewall

To simulate a misconfigured system commonly encountered in real environments, I disabled the Windows Firewall on the virtual machine.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 114145.png" width="750">
</p>

---

### 3️⃣ Create an Advanced Network Scan and Run a Baseline Scan

I logged into Tenable Vulnerability Management and created a new scan using a User Defined template scan.

- Scanner: LOCAL-SCAN-ENGINE-01
- Target: VM private IP address (10.0.0.140)

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 114358.png" width="750">
</p>

I configured the scan with Windows credentials for authenticated access and added Compliance Checks for DISA Windows 11 STIG v2r4.

To ensure the scan focused only on STIG compliance and completed quickly:

- All vulnerability plugins were disabled
- Only Policy Compliance → Windows Compliance Checks were enabled

I then ran the initial baseline scan.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 114510.png" width="750">
</p>

<a href="https://drive.google.com/file/d/1MM9jGHiBvGAKZ0dba7-3xNGm5EDhzUZZ/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_1_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 4️⃣ Investigate Scan Results and Identify the STIG

After reviewing the scan results, I identified a failed STIG: WN11-CC-000005.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 121348.png" width="750">
</p>

According to stigaview.com, Enabling camera access from the lock screen could allow for unauthorized use. Requiring logon will ensure the device is only used by authorized personnel.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 121951.png" width="750">
</p>

---

### 5️⃣ Manually Apply the STIG and Verify the Fix

To manually apply STIG WN11-CC-000005, Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >> Personalization >> "Prevent enabling lock screen camera" to "Enabled".

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 122459.png" width="750">
  <img src="screenshots/Screenshot 2025-12-31 202525.png" width="750">
  <img src="screenshots/Screenshot 2025-12-31 122646.png" width="750">  
</p>

After applying the change, I restarted the VM and ran the scan again to validate the fix.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 124336.png" width="750">
</p>


<a href="https://drive.google.com/file/d/1rXFAPjjNMlRzFxC1P3A-EXEBvW6rHyuP/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_2_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

## 6️⃣ Revert the Fix and Confirm Failure

To confirm that compliance with WN11-CC-000005 is dependent on the policy-backed registry enforcement applied by Local Group Policy, I reverted the system to a non-compliant state by removing the underlying registry value associated with the control.

The “Prevent enabling lock screen camera” policy is enforced through the following registry location:

`HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization`

When enabled, the policy creates the following value:

`NoLockScreenCamera (DWORD) = 1`

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 210134.png" width="750">
</p>

To revert the control and return it to a Not Configured state, I removed the policy-backed registry value using PowerShell:

```PowerShell
  Remove-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
  -Name "NoLockScreenCamera" `
  -ErrorAction SilentlyContinue
```

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 210336.png" width="750">
</p>

Removing this value cleared the Local Group Policy enforcement and restored the system’s default behavior. I verified that the policy now appeared as Not Configured within the Local Group Policy Editor.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 130449.png" width="750">
</p>

After reverting the configuration, I re-ran the authenticated STIG compliance scan. As expected, WN11-CC-000005 returned to a Failed state, confirming that the control’s compliance result is dependent on the presence of the policy-backed registry value.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 132221.png" width="750">
  <img src="screenshots/Screenshot 2025-12-31 132317.png" width="750">
</p>

<a href="https://drive.google.com/file/d/1oZY2sjutbp1n6nca-3eC4oXYcpBupn87/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_3_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 7️⃣ Generate and Apply the PowerShell Remediation

After validating the manual configuration and confirming the revert behavior, I translated the STIG requirements for WN11-CC-000005 into an automated PowerShell remediation script.

This control is enforced through a policy-backed registry value associated with an Administrative Template. Compliance is evaluated based on whether the required registry value is present and correctly configured, rather than whether the setting appears as explicitly enabled within the Local Group Policy Editor.

The script was designed to:

- Create the required policy registry path if it does not already exist
- Set the NoLockScreenCamera DWORD value to a STIG-compliant state
- Enforce the lock screen camera restriction programmatically without relying on the Local Group Policy Editor
- Verify the registry state after remediation
- Support repeatable automation during STIG compliance testing

---

To test the automation:

- I logged back into the virtual machine  
- Downloaded the PowerShell remediation script from my GitHub repository  
- Ran the script in an elevated PowerShell session


Before remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 215919.png" width="750">
</p>

After remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 220136.png" width="750">
</p>

After executing the remediation script, the required policy-backed registry value was successfully applied, enforcing the lock screen camera restriction. 

Although the Local Group Policy Editor continued to display the setting as Not Configured, the registry state confirmed that the control was actively enforced.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 134601.png" width="750">
</p>

I then re-ran the authenticated STIG compliance scan. The scan confirmed that WN11-CC-000005 returned to a Passed state, validating that registry-based enforcement alone is sufficient to satisfy the control requirement.

---

### 8️⃣ Confirm STIG Compliance via Re-Scan

After applying the PowerShell script, I ran another authenticated compliance scan in Tenable.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-31 141950.png" width="750">
  <img src="screenshots/Screenshot 2025-12-31 142033.png" width="750">
</p>

The scan confirmed that STIG WN11-CC-000005 was successfully applied and passed, demonstrating that the automated remediation was effective.

<a href="https://drive.google.com/file/d/13OHrkV8_ds3jVtsfDGmXXsuCXC234hY6/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_4_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>

<br>

---

### 9️⃣ Conclusion

This lab demonstrates a complete STIG suggesting, validation, and automation lifecycle. By manually implementing, reverting, and then automating the STIG control, I validated both my understanding of DISA STIG requirements and my ability to enforce them programmatically.


This workflow reflects real-world compliance operations where security controls must be validated manually, automated reliably, and continuously verified through authenticated scanning.
