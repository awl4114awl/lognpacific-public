<p align="center">
  <img
    src="https://github.com/awl4114awl/lognpacific-public/blob/main/cyber-range/threat-hunting-scenarios/Threat%20Hunt%20%E2%80%93%20Port%20of%20Entry/assets/Threat%20Hunt%20%E2%80%93%20Port%20of%20Entry.png"
    width="1000"
    alt="Threat Hunt – Port of Entry Cover Image"
  />
</p>

# 🛡️ Threat Hunt Report – Port of Entry

## Executive Summary

Azuki Import/Export experienced a targeted intrusion that resulted in the theft and exfiltration of sensitive supplier contracts and pricing data. The attacker gained access through exposed Remote Desktop Protocol (RDP), established persistence, harvested credentials, and exfiltrated data using a public cloud service. Shortly after the incident, a competitor undercut Azuki’s long-term shipping contract by exactly 3%, strongly suggesting data-driven corporate espionage. All activity was reconstructed using Microsoft Defender for Endpoint telemetry.

## Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

## Scope & Environment

- **Environment:** Azure-hosted Windows endpoints  
- **Data Sources:** Microsoft Defender for Endpoint (Advanced Hunting)  
- **Timeframe:** 2025-11-18 → 2025-11-20  

## Table of Contents

- [Hunt Overview](#hunt-overview)
- [MITRE ATT&CK Summary](#mitre-attck-summary)
- [Flag Analysis](#flag-analysis)
  - [🚩 Flag 1](#flag-1)
  - [🚩 Flag 2](#flag-2)
  - [🚩 Flag 3](#flag-3)
  - [🚩 Flag 4](#flag-4)
  - [🚩 Flag 5](#flag-5)
  - [🚩 Flag 6](#flag-6)
  - [🚩 Flag 7](#flag-7)
  - [🚩 Flag 8](#flag-8)
  - [🚩 Flag 9](#flag-9)
  - [🚩 Flag 10](#flag-10)
  - [🚩 Flag 11](#flag-11)
  - [🚩 Flag 12](#flag-12)
  - [🚩 Flag 13](#flag-13)
  - [🚩 Flag 14](#flag-14)
  - [🚩 Flag 15](#flag-15)
  - [🚩 Flag 16](#flag-16)
  - [🚩 Flag 17](#flag-17)
  - [🚩 Flag 18](#flag-18)
  - [🚩 Flag 19](#flag-19)
  - [🚩 Flag 20](#flag-20)
- [Detection Gaps & Recommendations](#detection-gaps--recommendations)
- [Final Assessment](#final-assessment)
- [Analyst Notes](#analyst-notes)

## Hunt Overview

This threat hunt investigated a targeted intrusion against Azuki Import/Export that resulted in the theft of sensitive supplier and pricing data. The attacker gained initial access via Remote Desktop Protocol, performed network reconnaissance, staged tools in hidden directories, and established persistence using scheduled tasks. Credential access was achieved through a renamed Mimikatz payload, followed by data collection, compression, and exfiltration over HTTPS to a public cloud service. Anti-forensic activity and a hidden administrator account were observed, indicating an intent to maintain long-term access and evade detection.

## MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | External Remote Services | T1133 | High |
| 2 | Valid Accounts | T1078 | High |
| 3 | System Network Configuration Discovery | T1016 | Medium |
| 4 | Data Staged: Local Data Staging | T1074.001 | High |
| 5 | Impair Defenses: Modify Tools | T1562.001 | High |
| 6 | Impair Defenses: Modify Tools | T1562.001 | High |
| 7 | Signed Binary Proxy Execution | T1218 | High |
| 8 | Scheduled Task/Job: Scheduled Task | T1053.005 | High |
| 9 | Scheduled Task/Job: Scheduled Task | T1053.005 | High |
| 10 | Application Layer Protocol | T1071 | High |
| 11 | Application Layer Protocol | T1071 | Medium |
| 12 | OS Credential Dumping: LSASS Memory | T1003.001 | Critical |
| 13 | OS Credential Dumping: LSASS Memory | T1003.001 | Critical |
| 14 | Archive Collected Data | T1560 | High |
| 15 | Exfiltration Over Web Service | T1567.002 | Critical |
| 16 | Indicator Removal on Host | T1070.001 | High |
| 17 | Create Account: Local Account | T1136.001 | High |
| 18 | Command and Scripting Interpreter: PowerShell | T1059.001 | High |
| 19 | Remote Services: RDP | T1021.001 | High |
| 20 | Remote Services: RDP | T1021.001 | High |

## Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="flag-1">🚩 <strong>Flag 1: Initial Access – Remote Access Source</strong></summary>

### Objective
Identify the external source used to gain initial access via Remote Desktop Protocol (RDP).

### Investigation
To identify the source of remote access, the DeviceLogonEvents table was queried.  
This table records authentication activity, including logon type, account used, and source IP address.

In Microsoft Defender for Endpoint, RDP logons are recorded with a `LogonType` value of RemoteInteractive.  
Filtering on this value allows isolation of remote desktop activity.

### KQL Query Used
```kql
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType, LogonType
| sort by Timestamp asc
````

### Finding

Analysis of the results revealed a successful remote interactive logon originating from the external IP address:

`88.97.178.12`

### Why It Matters

Identifying the source IP of initial access establishes the entry point of the intrusion.
This information can be used to block malicious traffic, correlate activity across incidents, and support attribution and containment efforts.

### Evidence

<p align="left">
  <img src="assets/flag 1.png" width="800" alt="Flag 1 – Initial Access" />
</p>

</details>

---

<details>
<summary id="flag-2">🚩 <strong>Flag 2: Initial Access – Compromised User Account</strong></summary>

### Objective
Identify the user account that was compromised and used during the initial Remote Desktop access.

### Investigation
After identifying a successful RemoteInteractive logon in Flag 1, the next step was to determine which credentials were used for that session.

The DeviceLogonEvents table includes an `AccountName` field that records the user associated with each authentication event.  
By extending the previous query to include this column, the compromised account can be identified.

### KQL Query Used
```kql
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType, LogonType, AccountName
| sort by Timestamp asc
````

### Finding

The Remote Desktop logon was performed using the following account:

`kenji.sato`

### Why It Matters

Identifying the compromised account defines the scope of unauthorized access and informs remediation actions such as password resets, privilege reviews, and audit of account activity across the environment.

### Evidence

<p align="left">
  <img src="assets/flag 2.png" width="800" alt="Flag 2 – Compromised User Account" />
</p>

</details>

---

<details>
<summary id="flag-3">🚩 Flag 3: Discovery – Network Reconnaissance</summary>

### Objective
Identify evidence of network reconnaissance activity performed after initial access.

### Investigation
After establishing access to the host, the next step for an attacker is typically to understand the local network environment.  
This includes identifying nearby systems, IP addresses, and MAC addresses that may be viable targets for lateral movement.

Network discovery activity is commonly performed using built-in operating system utilities.  
Because this activity involves command execution, the DeviceProcessEvents table was used to review process creation and command-line arguments.

The query focused on commands containing the string `arp`, which is frequently used to enumerate network neighbors.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "arp"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
````

### Finding

The attacker executed the following command to enumerate network neighbors:

`ARP.EXE -a`

### Why It Matters

The `arp -a` command displays a list of IP addresses and corresponding MAC addresses on the local subnet.
This activity indicates deliberate network reconnaissance and suggests the attacker was identifying potential targets for lateral movement.

### Evidence

<p align="left">
  <img src="assets/flag 3.png" width="800" alt="Flag 3 – Network Reconnaissance" />
</p>

</details>

---

<details>
<summary id="flag-4">🚩 Flag 4: Defense Evasion – Malware Staging Directory</summary>

### Objective
Identify the primary directory used by the attacker to stage malware and stolen data while evading detection.

### Investigation
After initial access and reconnaissance, attackers typically establish a hidden location on disk to store tools and collected data.  
This activity often involves creating directories and modifying their attributes to hide them from normal user view.

Because directory creation and attribute changes are performed through command execution, the DeviceProcessEvents table was used.  
The query focused on command-line activity containing the `attrib` command, which is commonly used to hide files and folders.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "attrib"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp asc
````

### Finding

Analysis of the results showed the creation and hiding of the following directory:

`C:\ProgramData\WindowsCache`

### Why It Matters

Attackers often create multiple temporary directories during an intrusion, but typically rely on one primary staging directory as their main workspace.
This directory is intentionally created, hidden, and reused to store malware, tools, and collected data.

In this case, `C:\ProgramData\WindowsCache` served as the attacker’s primary staging directory and was used throughout multiple phases of the attack, indicating deliberate defense evasion and operational planning.

### Evidence

<p align="left">
  <img src="assets/flag 4.png" width="800" alt="Flag 4 – Malware Staging Directory" />
</p>

</details>

---

<details>
<summary id="flag-5">🚩 Flag 5: Defense Evasion – File Extension Exclusions</summary>

### Objective
Determine whether the attacker modified Windows Defender settings to exclude specific file extensions from scanning.

### Investigation
Attackers commonly weaken endpoint defenses by configuring Windows Defender to ignore certain file types.  
These exclusions are stored in the Windows Registry under Defender’s exclusion settings.

Registry activity is recorded in the DeviceRegistryEvents table.  
The query focused on registry keys related to Defender file extension exclusions.

The `@` symbol was used to ensure the registry path was interpreted literally, as backslashes are treated as escape characters in KQL.

### KQL Query Used
```kql
DeviceRegistryEvents
| where DeviceName contains "azuki"
| where RegistryKey contains @"Windows Defender\Exclusions\Extensions"
| order by Timestamp asc
````

### Finding

The attacker added `3` file extension exclusions to Windows Defender.

### Why It Matters

By excluding specific file extensions from scanning, Windows Defender will ignore files matching those types.
This allows malicious scripts and executables to run without being inspected or blocked.

In this case, the exclusions enabled the attacker to execute tools and scripts while avoiding detection, representing a deliberate defense evasion technique.

### Evidence

<p align="left">
  <img src="assets/flag 5.png" width="800" alt="Flag 5 – Defender Extension Exclusions" />
</p>

</details>

---

<details>
<summary id="flag-6">🚩 Flag 6: Defense Evasion – Temporary Folder Exclusion</summary>

### Objective
Identify whether the attacker configured Windows Defender to exclude a directory used for staging and executing malicious tools.

### Investigation
Similar to file extension exclusions, attackers may weaken endpoint defenses by excluding entire directory paths from Windows Defender scanning.  
These exclusions are configured through the Windows Registry and recorded in the DeviceRegistryEvents table.

The investigation focused on registry keys associated with Defender path exclusions.

### KQL Query Used
```kql
DeviceRegistryEvents
| where RegistryKey contains @"Windows Defender\Exclusions\Paths"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
| sort by Timestamp asc
````

### Finding

The attacker added the following directory to Windows Defender’s exclusion list:

`C:\Users\KENJI~1.SAT\AppData\Local\Temp`

### Why It Matters

Temporary directories are commonly used by attackers to download, unpack, and execute malicious tools.
By excluding this folder from scanning, Windows Defender was prevented from inspecting any files placed within it.

This exclusion created a safe execution environment that enabled malware, scripts, and archived data to run undetected, representing a significant defense evasion technique.

### Evidence

<p align="left">
  <img src="assets/flag 6.png" width="800" alt="Flag 6 – Defender Path Exclusion" />
</p>

</details>

---

<details>
<summary id="flag-7">🚩 Flag 7: Defense Evasion – Download Utility Abuse</summary>

### Objective
Identify the Windows-native utility abused by the attacker to download malicious payloads while blending in with legitimate system activity.

### Investigation
Attackers frequently abuse built-in Windows utilities to retrieve malware, as these tools are trusted, signed, and commonly present on endpoints.  
This technique allows malicious activity to blend in with normal administrative behavior.

Because this activity involves process execution and network-related command lines, the DeviceProcessEvents table was queried.  
The investigation focused on command lines containing HTTP or HTTPS URLs, which commonly indicate file download activity.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "http" or ProcessCommandLine contains "https"
| project Timestamp, FileName, ProcessCommandLine, DeviceName
| order by Timestamp asc
````

### Finding

Analysis of the process execution data revealed that the attacker used the following Windows-native utility to download malware:

`certutil.exe

The command retrieved a malicious executable from an external server and saved it into the previously identified hidden staging directory.

### Why It Matters

Abusing legitimate Windows binaries to download malware allows attackers to evade basic detection controls and application allowlists.
This technique reduces the likelihood of alerts by avoiding the use of obvious third-party download tools and reinforces the attacker’s use of living-off-the-land techniques.

### Evidence

<p align="left">
  <img src="assets/flag 7.png" width="800" alt="Flag 7 – Download Utility Abuse" />
</p>

</details>

---

<details>
<summary id="flag-8">🚩 Flag 8: Persistence – Scheduled Task Name</summary>

### Objective
Identify the scheduled task created by the attacker to establish persistence across system logons and reboots.

### Investigation
Attackers commonly use scheduled tasks to maintain persistence because they survive reboots and can be configured to execute automatically under high-privilege accounts.

Scheduled task creation activity is recorded in the **DeviceProcessEvents** table.  
The investigation focused on executions of `schtasks.exe` and command lines containing task creation parameters.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "schtasks.exe" or ProcessCommandLine contains "/create"
| project Timestamp, FileName, ProcessCommandLine, DeviceName
| order by Timestamp asc
````

### Finding

Analysis of the task creation command revealed the following scheduled task name:

`Windows Update Check`

### Why It Matters

The task name closely resembles legitimate Windows maintenance activity, allowing it to blend into the system and avoid casual detection.
By configuring the task to run on user logon and execute malware from a hidden directory under the SYSTEM account, the attacker ensured reliable persistence with maximum privileges.

### Evidence

<p align="left">
  <img src="assets/flag 8.png" width="800" alt="Flag 8 – Scheduled Task Name" />
</p>

</details>

---

<details>
<summary id="flag-9">🚩 Flag 9: Persistence – Scheduled Task Target</summary>

### Objective
Identify the executable configured to run by the scheduled task used for persistence.

### Investigation
Scheduled task creation commands specify the program that will execute when the task runs.  
This value represents the persistence payload and reveals the exact malware location on disk.

Because this information is contained within the same task creation command identified in Flag 8, no additional query was required.  
The **DeviceProcessEvents** results were reviewed to identify the executable path specified in the task configuration.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "schtasks.exe" or ProcessCommandLine contains "/create"
| project Timestamp, FileName, ProcessCommandLine, DeviceName
| order by Timestamp asc
````

### Finding

The scheduled task was configured to execute the following file:

`C:\ProgramData\WindowsCache\svchost.exe`

### Why It Matters

The task target defines the malware that will automatically execute on user logon.
By placing the payload in a hidden staging directory and naming it `svchost.exe`, the attacker attempted to disguise malicious activity as a legitimate Windows process.

This configuration ensured the malware would persist across reboots and user sessions while remaining difficult to identify.

### Evidence

<p align="left">
  <img src="assets/flag 9.png" width="800" alt="Flag 9 – Scheduled Task Target" />
</p>

</details>

---

<details>
<summary id="flag-10">🚩 Flag 10: Command and Control – C2 Server Address</summary>

### Objective
Identify the external command-and-control server used by the attacker to communicate with the compromised system.

### Investigation
After the malware was downloaded and staged in the hidden directory identified in earlier flags, the next step was to determine whether it established outbound communication.

Outbound network connections initiated by processes are recorded in the **DeviceNetworkEvents** table.  
To isolate malicious activity, the investigation focused on network connections initiated by the suspicious executable located in the hidden staging directory.

### KQL Query Used
```kql
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath contains @"c:\programdata\windowscache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| sort by Timestamp asc
````

### Finding

The malware initiated outbound network communication to the following external IP address:

`78.141.196.6`

### Why It Matters

Command-and-control infrastructure enables attackers to remotely issue commands, receive stolen data, and maintain control over compromised systems.
Identifying the C2 server provides a critical opportunity for containment through network blocking and supports correlation with other malicious activity.

### Evidence

<p align="left">
  <img src="assets/flag 10.png" width="800" alt="Flag 10 – C2 Server Address" />
</p>

</details>

---

<details>
<summary id="flag-11">🚩 Flag 11: Command and Control – C2 Communication Port</summary>

### Objective
Identify the network port used by the malware for command-and-control communication.

### Investigation
C2 communication details, including destination ports, are captured in the **DeviceNetworkEvents** table.  
Because the same network activity identified in Flag 10 contains this information, no additional query was required.

The previously reviewed network events initiated by the malicious executable were examined for the destination port used during outbound communication.

### KQL Query Used
```kql
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where InitiatingProcessFileName == "svchost.exe"
| where InitiatingProcessFolderPath contains @"c:\programdata\windowscache"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| sort by Timestamp asc
````

### Finding

The malware communicated with its command-and-control server over the following port:

`443`

### Why It Matters

Port 443 is commonly used for HTTPS traffic and is typically allowed through firewalls.
Using this port allows command-and-control activity to blend in with legitimate encrypted web traffic, reducing the likelihood of detection by basic network controls.

### Evidence

<p align="left">
  <img src="assets/flag 11.png" width="800" alt="Flag 11 – C2 Communication Port" />
</p>

</details>

---

<details>
<summary id="flag-12">🚩 Flag 12: Credential Access – Credential Theft Tool</summary>

### Objective
Identify the tool used by the attacker to perform credential dumping on the compromised system.

### Investigation
Credential dumping requires a dedicated executable capable of extracting authentication material from system memory.  
Although LSASS memory access itself was not directly observable in this environment, the attacker still had to download and stage a credential theft tool prior to execution.

Because previously identified malware was stored in the staging directory, the investigation focused on newly created executables within that location.  
File creation activity is recorded in the **DeviceFileEvents** table.

### KQL Query Used
```kql
DeviceFileEvents
| where FolderPath contains "WindowsCache"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| sort by Timestamp asc
````

### Finding

Review of executable files staged in the attacker’s working directory identified the following credential theft tool:

`mm.exe`

### Why It Matters

Credential dumping tools are commonly renamed to short or generic filenames to evade signature-based detection.
The presence of `mm.exe` in the staging directory, combined with its timing within the attack chain, strongly indicates a renamed credential dumping utility used to harvest authentication material.

This activity represents a critical escalation of attacker capability and enables lateral movement and privilege abuse.

### Evidence

<p align="left">
  <img src="assets/flag 12.png" width="800" alt="Flag 12 – Credential Theft Tool" />
</p>

</details>

---

<details>
<summary id="flag-13">🚩 Flag 13: Credential Access – Memory Extraction Module</summary>

### Objective
Identify the credential dumping technique used by the attacker to extract authentication data from system memory.

### Investigation
After identifying the presence of a credential theft tool in the staging directory, the next step was to determine how that tool was used.  
Credential dumping activity is observable through process execution and command-line arguments.

The DeviceProcessEvents table was queried to review executions of staged executables and inspect their command-line parameters.  
The investigation focused on processes executed from the staging directory that contained recognizable credential dumping syntax.

### KQL Query Used
```kql
DeviceProcessEvents
| where FolderPath contains "WindowsCache"
| where FileName endswith ".exe"
| project Timestamp, FileName, FolderPath, ProcessCommandLine
| sort by Timestamp asc
````

### Finding

The process command line revealed use of the following credential extraction module:

`sekurlsa::logonpasswords`

### Why It Matters

Credential dumping frameworks commonly use a module-based syntax to specify extraction techniques.
The `sekurlsa::logonpasswords` module is specifically designed to extract cleartext passwords, NTLM hashes, and Kerberos tickets from LSASS memory.

Its presence confirms active credential dumping and indicates the attacker successfully accessed sensitive authentication material, enabling lateral movement and privilege escalation.

### Evidence

<p align="left">
  <img src="assets/flag 13.png" width="800" alt="Flag 13 – Memory Extraction Module" />
</p>

</details>

---

<details>
<summary id="flag-14">🚩 Flag 14: Collection – Data Staging Archive</summary>

### Objective
Identify the archive used by the attacker to stage stolen data prior to exfiltration.

### Investigation
After credential access, attackers typically collect and compress stolen data to prepare it for exfiltration.  
This activity commonly results in the creation of archive files within the attacker’s staging directory.

File creation events are recorded in the DeviceFileEvents table.  
The investigation focused on newly created `.zip` files within the previously identified staging directory.

### KQL Query Used
```kql
DeviceFileEvents
| where DeviceName contains "azuki"
| where ActionType == "FileCreated"
| where FileName endswith ".zip"
| where FolderPath contains @"C:\ProgramData\WindowsCache"
| project Timestamp, DeviceName, FileName, FolderPath
| order by Timestamp asc
````

### Finding

The attacker created the following archive file to stage collected data:

`export-data.zip`

### Why It Matters

Compressing stolen data into an archive simplifies exfiltration and reduces the number of outbound transfers required.
The presence of `export-data.zip` in the staging directory indicates deliberate preparation for data theft and confirms the collection phase of the attack.

### Evidence

<p align="left">
  <img src="assets/flag 14.png" width="800" alt="Flag 14 – Data Staging Archive" />
</p>

</details>

---

<details>
<summary id="flag-15">🚩 Flag 15: Exfiltration – Exfiltration Channel</summary>

### Objective
Identify the external service used by the attacker to exfiltrate stolen data.

### Investigation
After staging collected data into an archive, attackers must transmit that data outside the environment.  
This activity results in outbound network connections initiated by the malicious process.

Outbound connections and destination details are recorded in the DeviceNetworkEvents table.  
The investigation focused on network activity initiated by processes associated with the attacker’s staging directory.

### KQL Query Used
```kql
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where InitiatingProcessCommandLine contains "WindowsCache"
| project Timestamp, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| sort by Timestamp asc
````

### Finding

Analysis of outbound network traffic revealed that the stolen data was transmitted to the following service:

`Discord`

### Why It Matters

Cloud-based services that support file uploads are frequently abused for data exfiltration because their traffic blends in with legitimate HTTPS activity.
Using a well-known platform reduces the likelihood of detection by basic network monitoring and complicates data loss prevention efforts.

Identifying the exfiltration channel helps define incident scope and supports containment and response actions.

### Evidence

<p align="left">
  <img src="assets/flag 15.png" width="800" alt="Flag 15 – Exfiltration Channel" />
</p>

</details>

---

<details>
<summary id="flag-16">🚩 Flag 16: Anti-Forensics – Log Tampering</summary>

### Objective
Identify evidence of event log tampering performed to conceal attacker activity.

### Investigation
Attackers often attempt to remove forensic evidence near the end of an intrusion by clearing Windows event logs.  
Log management commands executed on the system are recorded in the DeviceProcessEvents table.

The investigation focused on process executions containing the `wevtutil` utility, which is commonly abused to clear event logs.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
````

### Finding

The attacker executed a command to clear the following Windows event log:

`Security`

### Why It Matters

The Security event log contains critical forensic data, including authentication events, privilege changes, and remote access activity.
Clearing this log significantly degrades an investigator’s ability to reconstruct attacker actions and indicates deliberate anti-forensic behavior.

The timing of this activity suggests the attacker attempted to cover their tracks after completing credential access and data exfiltration.

### Evidence

<p align="left">
  <img src="assets/flag 16.png" width="800" alt="Flag 16 – Log Tampering" />
</p>

</details>

---

<details>
<summary id="flag-17">🚩 Flag 17: Impact – Persistence Account</summary>

### Objective
Identify evidence of a backdoor account created to maintain long-term access to the compromised system.

### Investigation
After completing data exfiltration and anti-forensic activity, attackers often establish alternate access methods to regain entry in the future.  
One common technique is the creation of a local administrator account that can be used independently of previously compromised credentials.

Account and group modification commands are recorded in the DeviceProcessEvents table.  
The investigation focused on process executions containing parameters used to add users to privileged local groups.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "/add"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
````

### Finding

The attacker created and added the following account to the local Administrators group:

support

### Why It Matters

Creating a hidden local administrator account provides persistent, high-privilege access that bypasses normal authentication controls.
This technique allows an attacker to return even if the originally compromised credentials are reset or access paths are closed.

The presence of this account represents a lasting security impact and requires immediate remediation.

### Evidence

<p align="left">
  <img src="assets/flag 17.png" width="800" alt="Flag 17 – Persistence Account" />
</p>

</details>

---

<details>
<summary id="flag-18">🚩 Flag 18: Execution – Malicious Script</summary>

### Objective
Identify the script used by the attacker to automate execution of the attack chain.

### Investigation
Attackers frequently use scripting languages to automate malicious activity and bypass interactive controls.  
Script creation activity is recorded in the **DeviceFileEvents** table, including file name, location, and the process responsible for execution.

The investigation focused on newly created PowerShell script files located in temporary directories, which are commonly abused for short-lived execution artifacts.

### KQL Query Used
```kql
DeviceFileEvents
| where DeviceName contains "azuki"
| where FileName endswith ".ps1"
| where ActionType == "FileCreated"
| where FolderPath contains "temp"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp asc
````

### Finding

The attacker created and executed the following PowerShell script:

wupdate.ps1

The associated process command line showed PowerShell executing the script with hidden window settings and execution policy bypass enabled.

### Why It Matters

PowerShell execution with execution policy bypass and hidden window settings indicates intentional evasion of built-in security controls.
The presence of this script in the temporary directory suggests it was used as an initial automation mechanism to launch and coordinate subsequent attack activity.

This script represents the execution entry point for the broader intrusion.

### Evidence

<p align="left">
  <img src="assets/flag 18.png" width="800" alt="Flag 18 – Malicious Script Execution" />
</p>

</details>

---

<details>
<summary id="flag-19">🚩 Flag 19: Lateral Movement – Secondary Target</summary>

### Objective
Identify the secondary system targeted by the attacker for lateral movement.

### Investigation
After obtaining credentials and establishing persistence, attackers often attempt to move laterally to other systems within the environment.  
Lateral movement activity is observable through command execution related to remote access and credential use.

The **DeviceProcessEvents** table was queried to identify commands associated with remote desktop access and stored credential usage.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "cmdkey" or ProcessCommandLine contains "mstsc"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
````

### Finding

The attacker attempted lateral movement to the following internal IP address:

10.1.0.188

### Why It Matters

Identifying lateral movement targets provides insight into attacker intent and highlights additional systems that may be at risk.
This activity indicates the attacker was expanding access beyond the initially compromised host and searching for systems with higher value or broader privileges.

### Evidence

<p align="left">
  <img src="assets/flag 19.png" width="800" alt="Flag 19 – Lateral Movement Target" />
</p>

</details>

---

<details>
<summary id="flag-20">🚩 Flag 20: Lateral Movement – Remote Access Tool</summary>

### Objective
Identify the tool used by the attacker to perform lateral movement to a secondary system.

### Investigation
Attackers often rely on built-in remote access tools to move laterally, as these utilities blend in with legitimate administrative activity.  
Process execution related to remote desktop access is recorded in the DeviceProcessEvents table.

The investigation focused on processes executed with command-line arguments referencing the previously identified lateral movement target.

### KQL Query Used
```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "10.1.0.188"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
````

### Finding

The attacker used the following remote access tool for lateral movement:

mstsc.exe

### Why It Matters

Using a native remote desktop client allows lateral movement activity to blend into normal administrative behavior.
This technique reduces the likelihood of detection and confirms the attacker leveraged legitimate tools to expand access within the environment.

### Evidence

<p align="left">
  <img src="assets/flag 20.png" width="800" alt="Flag 20 – Lateral Movement Tool" />
</p>

</details>

---

## Detection Gaps & Recommendations

### Observed Gaps
- External Remote Desktop access was exposed without sufficient access controls or network restrictions.
- Windows Defender protections were modified without alerting or enforcement to prevent exclusion abuse.
- PowerShell execution with execution policy bypass and hidden windows was not blocked or alerted.
- Outbound HTTPS traffic to non-business cloud services was not restricted or monitored.
- Local administrator account creation did not generate sufficient visibility or alerts.

### Recommendations
- Restrict or disable external RDP access and enforce VPN, MFA, and IP allowlisting for remote administration.
- Enable Defender tamper protection and alerting for changes to exclusion paths and extensions.
- Implement PowerShell constrained language mode and alert on execution policy bypass usage.
- Monitor and restrict outbound connections to high-risk cloud services used for data exfiltration.
- Alert on local account creation and administrator group membership changes.

---

## Final Assessment

This intrusion demonstrates a methodical and low-noise attack using legitimate system tools to evade detection and maintain persistence. The attacker successfully progressed through initial access, credential theft, data exfiltration, and anti-forensic cleanup before attempting lateral movement. While endpoint telemetry allowed full reconstruction of the attack, gaps in preventive controls enabled the compromise to succeed. Strengthening identity protection, endpoint hardening, and outbound network monitoring would significantly reduce the likelihood and impact of similar attacks.
