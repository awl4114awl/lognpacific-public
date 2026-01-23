# Step By Step STIG Automation for STIG ID: WN11-CC-000327

## ℹ️ Overview

This lab was carried out in The Cyber Range, an Azure-hosted enterprise environment where I replicate real-world detection, investigation, and remediation workflows. In this scenario, I focused on STIG automation using PowerShell combined with Tenable authenticated scanning.

To create a realistic compliance and remediation exercise, I deliberately disabled the Windows Firewall on a Windows 11 Pro virtual machine. I then worked through a structured STIG implementation lifecycle that mirrors how compliance controls are identified, validated, and enforced in an enterprise environment.

The workflow included:
- Scanning the VM with a Windows 11 STIG Audit Policy
- Reviewing scan results and selecting a failed STIG (WN11-CC-000327)
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
| VM Name | win11-STIG-vm |
| OS Image | Windows 11 25H2 Pro |
| Region | East US 2 |
| VM Size | Standard DS1 v2 (1 vCPU, 3.5 GiB RAM) |
| Security Type | Trusted Launch (Secure Boot + vTPM Enabled) |
| Network | Cyber-Range-VNet / Cyber-Range-Subnet |
| Public IP | 172.177.124.128 |
| Private IP | 10.0.0.13 |
| Disk Encryption | Disabled |
| Auto-Shutdown | Not Enabled |
| Extensions | AzurePolicyforWindows |

---

### 2️⃣ Disable the Windows Firewall

To simulate a misconfigured system commonly encountered in real environments, I disabled the Windows Firewall on the virtual machine.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-19 135931.png" width="750">
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
  <img src="screenshots/Screenshot 2025-12-20 105721.png" width="750">
</p>

<a href="https://drive.google.com/file/d/1K2mylXdT2HgxtbzeZf9HcQpt6-mls8Qe/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_1_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 4️⃣ Investigate Scan Results and Identify the STIG

After reviewing the scan results, I identified a failed STIG: WN11-CC-000327.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-20 133356.png" width="750">
</p>

According to stigaview.com, Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling PowerShell Transcription will record detailed information from the processing of PowerShell commands and scripts. This can provide additional detail when malware has run on a system.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-20 133710.png" width="750">
</p>

---

### 5️⃣ Manually Apply the STIG and Verify the Fix

To manually apply STIG WN11-CC-000327, Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> "Turn on PowerShell Transcription" to "Enabled".

Specify the Transcript output directory to point to a Central Log Server or another secure location to prevent user access.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-21 142204.png" width="750">
  <img src="screenshots/Screenshot 2025-12-21 142259.png" width="750">
</p>

After applying the change, I restarted the VM and ran the scan again to validate the fix.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-22 072429.png" width="750">
  <img src="screenshots/Screenshot 2025-12-22 072449.png" width="750">
</p>


<a href="https://drive.google.com/file/d/1oc0XOm24gueNBWsA6BHB9NcwsAEvNc4P/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_2_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 6️⃣ Revert the Fix and Confirm Failure

Once the STIG passed successfully, I reverted the configuration to confirm the control would fail again. To validate that the compliance finding was directly tied to the registry-based policy values, I reverted the configuration by disabling PowerShell transcription at the registry level.

To disable transcription, the EnableTranscripting value must be set to 0. Any configured transcript output directory can optionally be removed to fully revert the policy.

#### Step 1: Check if the policy key exists

```powershell
Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
````

**What this does:**
Checks whether the registry location used by Group Policy to control PowerShell Transcription exists.

**Result:** `True`

**Meaning:**

* The system has a policy-backed configuration location for PowerShell Transcription
* The setting can be enforced via registry changes rather than the Local Group Policy Editor
* Compliance tools such as Tenable evaluate this registry path directly

---

#### Step 2: Read the current transcription configuration

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
```

**What this does:**
Displays the current policy values controlling PowerShell Transcription.

**Observed state:**

* `EnableTranscripting : 1`
* `OutputDirectory : <configured>`

**Meaning:**

* PowerShell Transcription was enabled
* Transcripts were being written to a defined directory
* This configuration would cause STIG WN11-CC-000327 to pass

---

#### Step 3: Disable PowerShell Transcription

```powershell
Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "EnableTranscripting" `
  -Type DWord `
  -Value 0
```

**What this does:**

* Disables PowerShell Transcription by setting the policy value to `0`
* Functionally equivalent to setting
  *Turn on PowerShell Transcription → Disabled* in Group Policy

**Why this matters:**

* This change directly impacts what compliance scanners evaluate
* No GUI interaction is required

---

#### Step 4: Remove the transcript output directory

```powershell
Remove-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "OutputDirectory" `
  -ErrorAction SilentlyContinue
```

**What this does:**

* Removes the configured transcript storage location
* Ensures no residual transcription configuration remains

**Why this is done:**

* Prevents partial or ambiguous policy states
* Makes the STIG failure condition explicit

---

#### Step 5: Verify the configuration change

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
```

**What this confirms:**

* `EnableTranscripting : 0`
* `OutputDirectory` is no longer present

**Meaning:**

* PowerShell Transcription is disabled
* The system should now fail STIG WN11-CC-000327
* This confirms the control is enforced through registry-based Group Policy values

---

<p align="left">
  <img src="screenshots/Screenshot 2025-12-22 084203.png" width="750">
</p>

PowerShell Transcription was disabled by modifying the registry-based Group Policy values, setting `EnableTranscripting` to `0` and removing the configured output directory. This confirms that STIG WN11-CC-000327 can be programmatically enforced without using the Local Group Policy Editor.

After applying the change, I rebooted the system to ensure the policy was fully applied. I then re-ran the authenticated STIG compliance scan.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-22 101021.png" width="750">
  <img src="screenshots/Screenshot 2025-12-22 105847.png" width="750">
</p>

As expected, STIG WN11-CC-000327 returned to a failed state, confirming that the control is enforced entirely through registry-based Group Policy values.

<a href="https://drive.google.com/file/d/16IQSvMKhTY4LMkN-JP6BNmOY37R7uM0e/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_3_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>
<br>

---

### 7️⃣ Generate and Apply the PowerShell Remediation

After validating the manual fix, I translated the STIG requirements into an automated PowerShell remediation script.

This control is enforced through registry-based Group Policy values, so the script was designed to configure the setting programmatically rather than relying on the Local Group Policy Editor.

The script was designed to:
- Enable PowerShell Transcription in accordance with STIG WN11-CC-000327
- Configure the transcript output directory to a secure location to prevent user modification
- Enable invocation headers to capture additional execution context within transcripts
- Create required registry policy paths if they do not already exist
- Verify the effective policy configuration after applying the changes

To test the automation:
- I logged back into the VM
- Downloaded the PowerShell remediation script from my GitHub repository
- Ran the script in an elevated PowerShell session

Before remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-22 105720.png" width="750">
</p>

After remediation:
<p align="left">
  <img src="screenshots/Screenshot 2025-12-22 110732.png" width="750">
</p>

---

### 8️⃣ Confirm STIG Compliance via Re-Scan

After applying the PowerShell script, I ran another authenticated compliance scan in Tenable.

<p align="left">
  <img src="screenshots/Screenshot 2025-12-22 112129.png" width="750">
  <img src="screenshots/Screenshot 2025-12-22 125154.png" width="750">
  <img src="screenshots/Screenshot 2025-12-22 125322.png" width="750">  
</p>

The scan confirmed that STIG WN11-AC-000010 was successfully applied and passed, demonstrating that the automated remediation was effective.

<a href="https://drive.google.com/file/d/1wgLoENq7SWPg5U1GYaMswpOBW188UFQn/view?usp=drive_link">
  <img src="https://img.shields.io/badge/wn11_stig_vm_scan_4_results-0061FF?style=for-the-badge&logo=adobeacrobatreader&logoColor=white">
</a>

<br>

---

### 9️⃣ Conclusion

This lab demonstrates a complete STIG suggesting, validation, and automation lifecycle. By manually implementing, reverting, and then automating the STIG control, I validated both my understanding of DISA STIG requirements and my ability to enforce them programmatically.

This workflow reflects real-world compliance operations where security controls must be validated manually, automated reliably, and continuously verified through authenticated scanning.



