# Step By Step STIG Automation for STIG ID: WN11-AC-000010

## ℹ️ Overview

This lab was carried out in The Cyber Range, an Azure-hosted enterprise environment where I replicate real-world detection, investigation, and remediation workflows. In this scenario, I focused on STIG automation using PowerShell combined with Tenable authenticated scanning.

To create a realistic compliance and remediation exercise, I deliberately disabled the Windows Firewall on a Windows 11 Pro virtual machine. I then worked through a structured STIG implementation lifecycle that mirrors how compliance controls are identified, validated, and enforced in an enterprise environment.

The workflow included:
- Scanning the VM with a Windows 11 STIG Audit Policy
- Reviewing scan results and selecting a failed STIG (WN11-AC-000010)
- Implementing the STIG manually and validating success
- Reverting the fix to confirm failure
- Automating the remediation using PowerShell
- Re-scanning to confirm successful enforcement

Through this lab, I demonstrate my ability to interpret STIG requirements, manually validate security controls, translate policy guidance into registry-level configuration changes, and automate compliance enforcement using PowerShell.

---

## Lab Workflow

### 1️⃣ Provision the Windows 11 Virtual Machine

I provisioned a Windows 11 Pro virtual machine in Microsoft Azure using the Cyber Range infrastructure.

| Component | Details |
|---------|--------|
| VM Name | Windows-11-STIG-vm |
| OS Image | Windows 11 25H2 Pro |
| Region | East US 2 |
| VM Size | Standard DS1 v2 (1 vCPU, 3.5 GiB RAM) |
| Security Type | Trusted Launch (Secure Boot + vTPM Enabled) |
| Network | Cyber-Range-VNet / Cyber-Range-Subnet |
| Public IP | 172.172.13.232 |
| Private IP | 10.0.0.13 |
| Disk Encryption | Disabled |
| Auto-Shutdown | Not Enabled |
| Extensions | AzurePolicyforWindows |

---

### 2️⃣ Disable the Windows Firewall

To simulate a misconfigured system commonly encountered in real environments, I disabled the Windows Firewall on the virtual machine.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-18 112821.png" width="750">
</p>

---

### 3️⃣ Create an Advanced Network Scan and Run a Baseline Scan

I logged into Tenable Vulnerability Management and created a new scan using a User Defined template scan.

- Scanner: LOCAL-SCAN-ENGINE-01
- Target: VM private IP address (10.0.0.13)

<p align="left">
  <img src="screenshots/Screenshot 2025-12-10 144503.png" width="750">
</p>

I configured the scan with Windows credentials for authenticated access and added Compliance Checks for DISA Windows 11 STIG v2r4.

To ensure the scan focused only on STIG compliance and completed quickly:

- All vulnerability plugins were disabled
- Only Policy Compliance → Windows Compliance Checks were enabled

I then ran the initial baseline scan.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-18 113631.png" width="750">
</p>

<a href="https://drive.google.com/file/d/1A_GZqNS_3LDfHcToyr3NYjMBHREczY1Y/view?usp=drive_link">
  <img src="https://img.shields.io/badge/windows_11_stig_vm_scan_1_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 4️⃣ Investigate Scan Results and Identify the STIG

After reviewing the scan results, I identified a failed STIG: WN11-SO-000070.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-18 134017.png" width="750">
</p>

According to stigaview.com, The account lockout feature, when enabled, prevents brute-force password attacks on the system. The higher this value is, the less effective the account lockout feature will be in protecting the local system. The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-18 114101.png" width="750">
</p>

---

### 5️⃣ Manually Apply the STIG and Verify the Fix

To manually apply STIG WN11-AC-000010, Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Account lockout threshold" to "3" or less invalid logon attempts (excluding "0" which is unacceptable).

<p align="left">
  <img src="screenshots/Screenshot 2025-12-18 134802.png" width="750">
</p>

After applying the change, I restarted the VM and ran the scan again to validate the fix.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-18 182753.png" width="750">
  <img src="screenshots/Screenshot 2025-12-18 182906.png" width="750">
</p>


<a href="https://drive.google.com/file/d/14IOHAYEyNTxGhE037RJ0m-eLSuxo9mYp/view?usp=drive_link">
  <img src="https://img.shields.io/badge/windows_11_stig_vm_scan_2_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 6️⃣ Revert the Fix and Confirm Failure

Once the STIG passed successfully, I reverted the configuration to confirm the control would fail again. This time, the setting was reverted using the command line to directly modify the account lockout policy.

I opened an elevated Command Prompt and ran the following command to disable account lockout:

```powershell
'net accounts /lockoutthreshold:0'
```

<p align="left">
  <img src="screenshots/Screenshot 2025-12-19 089725.png" width="750">
</p>

Setting the lockout threshold to 0 disables the account lockout feature entirely, which is non-compliant with STIG requirements.

After applying the change, I rebooted the system to ensure the policy was fully applied. 

I then re-ran the authenticated STIG compliance scan.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-19 081715.png" width="750">
  <img src="screenshots/Screenshot 2025-12-19 092601.png" width="750">
</p>

The scan confirmed that STIG WN11-AC-000010 failed again, validating both detection accuracy and the effectiveness of the revert process.

<a href="https://drive.google.com/file/d/1Iics71vURfjNv_wZHY4MGO1Yj_LN-wM6/view?usp=drive_link">
  <img src="https://img.shields.io/badge/windows_11_stig_vm_scan_3_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 7️⃣ Generate and Apply the PowerShell Remediation

After validating the manual fix, I translated the STIG requirements into an automated PowerShell remediation script.

The script was designed to:

- Enforce a STIG-compliant account lockout threshold of 3 invalid logon attempts or fewer
- Explicitly avoid 0, which disables account lockout and is non-compliant
- Apply the policy using net accounts to ensure the setting is written to the local security policy
- Verify the effective configuration after applying the change
- Recommend a reboot prior to re-scanning to ensure consistent enforcement

To test the automation:

- I logged back into the VM
- Downloaded the PowerShell remediation script from my GitHub repository
- Ran the script in an elevated PowerShell session

Before remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-19 094538.png" width="750">
</p>

After remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-19 094750.png" width="750">
</p>

---

### 8️⃣ Confirm STIG Compliance via Re-Scan

After applying the PowerShell script, I ran another authenticated compliance scan in Tenable.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-19 095423.png" width="750">
  <img src="screenshots/Screenshot 2025-12-19 111627.png" width="750">
  <img src="screenshots/Screenshot 2025-12-19 111809.png" width="750">  
</p>

The scan confirmed that STIG WN11-AC-000010 was successfully applied and passed, demonstrating that the automated remediation was effective.

<a href="https://drive.google.com/file/d/1ioxDABvQUBKuyDZ0UCd13v_g6yHcwwoH/view?usp=drive_link">
  <img src="https://img.shields.io/badge/windows_11_stig_vm_scan_4_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>

<br>

---

### 9️⃣ Conclusion

This lab demonstrates a complete STIG suggesting, validation, and automation lifecycle. By manually implementing, reverting, and then automating the STIG control, I validated both my understanding of DISA STIG requirements and my ability to enforce them programmatically.

This workflow reflects real-world compliance operations where security controls must be validated manually, automated reliably, and continuously verified through authenticated scanning.



