<p align="center">
  <img src="assets/Helpdesk Deception.png" width="1000">
</p>

# Threat Hunt Report – Support Tool Discovery to Persistence

## Executive Summary

This threat hunt reconstructed a user-space intrusion on `gab-intern-vm` in which a PowerShell script named `SupportTool.ps1` was executed from the Downloads directory under the guise of support or diagnostic activity. The operator performed host discovery, privilege mapping, session enumeration, storage assessment, runtime process inventory, outbound connectivity validation, artifact staging, simulated upload activity, and persistence establishment through both a scheduled task and a user-scope Run key. A narrative artifact was later dropped to make the activity appear legitimate. All activity was reconstructed through Microsoft Defender for Endpoint telemetry using Log Analytics Workspace queries.

## Hunt Objectives

* Identify the initial suspicious execution chain on the affected host
* Correlate discovery, staging, transfer testing, and persistence behavior
* Map observed activity to MITRE ATT&CK techniques
* Document evidence, detection gaps, and response opportunities

## Scope & Environment

* **Environment:** Azure-hosted Windows endpoint
* **Primary Host:** `gab-intern-vm`
* **Data Sources:** Microsoft Defender for Endpoint via Log Analytics Workspace
* **Tables Used:** `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`
* **Timeframe:** 2025-10-01 → 2025-10-15

## Table of Contents

* [Hunt Overview](#hunt-overview)
* [MITRE ATT&CK Summary](#mitre-attck-summary)
* [Flag Analysis](#flag-analysis)

  * [⚐ Flag 0](#flag-0)
  * [⚐ Flag 1](#flag-1)
  * [⚐ Flag 2](#flag-2)
  * [⚐ Flag 3](#flag-3)
  * [⚐ Flag 4](#flag-4)
  * [⚐ Flag 5](#flag-5)
  * [⚐ Flag 6](#flag-6)
  * [⚐ Flag 7](#flag-7)
  * [⚐ Flag 8](#flag-8)
  * [⚐ Flag 9](#flag-9)
  * [⚐ Flag 10](#flag-10)
  * [⚐ Flag 11](#flag-11)
  * [⚐ Flag 12](#flag-12)
  * [⚐ Flag 13](#flag-13)
  * [⚐ Flag 14](#flag-14)
  * [⚐ Flag 15](#flag-15)
* [Detection Gaps & Recommendations](#detection-gaps--recommendations)
* [Final Assessment](#final-assessment)
* [Analyst Notes](#analyst-notes)

## Hunt Overview

This threat hunt investigated a staged intrusion centered on a suspicious PowerShell script executed from a user Downloads directory on `gab-intern-vm`. The operator used the script as an entry point for a low-noise discovery sequence that included clipboard probing, account and privilege checks, session enumeration, logical disk assessment, process inventory, and connectivity testing. Collected artifacts were staged into a ZIP archive, outbound HTTPS transfer capability was tested against a public service, and persistence was established using both a logon-triggered scheduled task and a user-level Run key. The activity concluded with the creation of a support-themed log artifact intended to provide a plausible explanation for the suspicious operations.

## MITRE ATT&CK Summary

| Flag | Technique Category                                                    | MITRE ID  | Priority |
| ---: | --------------------------------------------------------------------- | --------- | -------- |
|    0 | User Execution                                                        | T1204     | High     |
|    1 | Command and Scripting Interpreter: PowerShell                         | T1059.001 | High     |
|    2 | Impair Defenses                                                       | T1562     | Medium   |
|    3 | Clipboard Data                                                        | T1115     | High     |
|    4 | System Owner/User Discovery                                           | T1033     | Medium   |
|    5 | File and Directory Discovery                                          | T1083     | Medium   |
|    6 | System Network Discovery                                              | T1016     | Medium   |
|    7 | System Owner/User Discovery                                           | T1033     | Medium   |
|    8 | Process Discovery                                                     | T1057     | Medium   |
|    9 | Permission Groups Discovery                                           | T1069     | Medium   |
|   10 | Application Layer Protocol                                            | T1071     | Medium   |
|   11 | Data Staged: Local Data Staging                                       | T1074.001 | High     |
|   12 | Exfiltration Over Web Service                                         | T1567.002 | High     |
|   13 | Scheduled Task/Job: Scheduled Task                                    | T1053.005 | High     |
|   14 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | High     |
|   15 | Masquerading                                                          | T1036     | Medium   |

## Flag Analysis

*All flags below are collapsible for readability.*

---

<details>
<summary id="flag-0">⚐ <strong>Flag 0: Starting Point – Suspicious Host Identification</strong></summary>

### Objective

Identify the most suspicious host tied to support-themed executions from a user Downloads directory.

### Investigation

The initial hunt objective was to locate the endpoint most strongly associated with suspicious tool execution during the first half of October 2025. Because the scenario referenced support-themed artifacts executed from a Downloads path, the investigation began in `DeviceProcessEvents`.

The query filtered for process executions with either `FolderPath` or `ProcessCommandLine` referencing `\Downloads\`, then further narrowed to support-themed keywords such as `support`, `help`, `desk`, and `tool`.

### KQL Query Used

```kql
DeviceProcessEvents 
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FolderPath has @"\Downloads\" 
    or ProcessCommandLine has @"\Downloads\"
| where ProcessCommandLine has_any ("Downloads", "support", "help", "desk", "tool")
    or FileName has_any ("Downloads", "support", "help", "desk", "tool")
```

### Finding

The host most strongly associated with this activity was:

`gab-intern-vm`

### Why It Matters

Identifying the correct starting host defines investigative scope and prevents chasing unrelated telemetry. In this case, `gab-intern-vm` became the anchor point for the remainder of the attack reconstruction.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 135217.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-1">⚐ <strong>Flag 1: Initial Execution – First Suspicious CLI Parameter</strong></summary>

### Objective

Identify the first command-line parameter used when the suspicious program was executed.

### Investigation

After isolating `gab-intern-vm`, the next step was to reconstruct the earliest suspicious execution from the Downloads directory. Because the likely execution would be preserved in process creation telemetry, `DeviceProcessEvents` was queried and sorted ascending by timestamp.

### KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FolderPath has @"\Downloads\" 
    or ProcessCommandLine has @"\Downloads\"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

### Finding

The earliest suspicious PowerShell execution used the first parameter:

`-ExecutionPolicy`

### Why It Matters

Use of `-ExecutionPolicy` in this context indicates deliberate script execution control, commonly used to bypass restrictive PowerShell policy settings and run a script from user space without normal guardrails.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 135535.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-2">⚐ <strong>Flag 2: Defense Evasion – Tamper-Themed Artifact</strong></summary>

### Objective

Identify the file associated with the defense-related exploit or tamper narrative.

### Investigation

Because the flag referenced a manually accessed file related to tampering, the investigation pivoted to `DeviceFileEvents`. The query focused on files containing the string `tamper` and limited results to actions initiated by plausible user-space processes such as PowerShell, Explorer, or Notepad.

### KQL Query Used

```kql
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between (datetime(2025-10-01)..datetime(2025-10-15))
| where InitiatingProcessFileName in ("powershell.exe", "explorer.exe", "notepad.exe") 
    and FileName contains "tamper"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### Finding

The file associated with the exploit was:

`DefenderTamperArtifact.lnk`

### Why It Matters

This artifact suggests an intent to frame or simulate defense tampering without proving an actual configuration change. It serves as an indicator of operator intent and narrative shaping.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 140030.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-3">⚐ <strong>Flag 3: Collection – Clipboard Probe</strong></summary>

### Objective

Identify the full command used to probe clipboard contents for easily accessible data.

### Investigation

The hint pointed toward clipboard access, so the investigation remained in `DeviceProcessEvents` and filtered for `clip` within command-line data. This surfaced a PowerShell command explicitly querying clipboard contents.

### KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine contains "clip"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

### Finding

The command used for the clipboard probe was:

`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`

### Why It Matters

Clipboard probing is a low-effort collection step used to capture copied secrets such as passwords, API keys, or other transient data. The use of `-Sta` and suppressed output indicates deliberate, quiet access.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 140228.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-4">⚐ <strong>Flag 4: Discovery – Host Context Recon Timestamp</strong></summary>

### Objective

Determine when host or user context reconnaissance last occurred for the targeted pattern.

### Investigation

The hunt shifted into discovery telemetry. `DeviceProcessEvents` was queried for common host context and session discovery commands such as `whoami`, `query user`, `quser`, and `qwinsta`, then sorted to evaluate the most relevant event tied to the hint.

### KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("qwi", "whoami", "query user", "quser", "qwinsta", "hostname", "systeminfo")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

### Finding

The relevant recon timestamp identified for this activity was:

`2025-10-09T12:51:44.3425653Z`

### Why It Matters

This timestamp anchors the beginning of a broader host and session discovery burst and helps correlate later commands to the same operator workflow.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 140934.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-5">⚐ <strong>Flag 5: Discovery – Storage Surface Mapping</strong></summary>

### Objective

Identify the second command tied to storage assessment activity on the host.

### Investigation

To reconstruct storage discovery, process executions were reviewed in a narrow time window surrounding the recon burst. This exposed WMIC-based logical disk enumeration.

### KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:00:00Z))
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### Finding

The second command tied to this activity was:

`"cmd.exe" /c wmic logicaldisk get name,freespace,size`

### Why It Matters

Logical disk enumeration reveals drive letters, free space, and disk size, which helps an operator identify where useful data may reside and which locations are suitable for staging.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 141452.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-6">⚐ <strong>Flag 6: Discovery – Connectivity & Name Resolution Parent</strong></summary>

### Objective

Identify the initiating parent process tied to connectivity and name resolution validation.

### Investigation

The focus shifted to network reachability checks such as `nslookup`. The query reviewed process creation telemetry for connectivity-related commands and projected both the initiating process and its parent chain.

### KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where InitiatingProcessFileName in ("powershell.exe","cmd.exe") 
| where ProcessCommandLine has_any ("ping","nslookup")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

### Finding

The initiating parent process was:

`RuntimeBroker.exe`

### Why It Matters

A process tree in which `RuntimeBroker.exe` leads into PowerShell and then `cmd.exe /c nslookup ...` is unusual and helps distinguish malicious operator-driven discovery from ordinary administrative use.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 154104.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-7">⚐ <strong>Flag 7: Discovery – Interactive Session Discovery Process ID</strong></summary>

### Objective

Identify the unique ID of the initiating process responsible for session enumeration activity.

### Investigation

The investigation isolated session-related discovery commands including `query session`, `qwinsta`, and `quser`. By projecting both `InitiatingProcessId` and `InitiatingProcessUniqueId`, the persistent process identity behind multiple recon commands could be established.

### KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:45:00Z) .. datetime(2025-10-09T13:05:00Z))
| where ProcessCommandLine has_any ("query session","qwinsta","quser","query user")
   or FileName in~ ("query.exe","qwinsta.exe","quser.exe")
| project TimeGenerated, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          InitiatingProcessId, InitiatingProcessUniqueId
| order by TimeGenerated asc
```

### Finding

The unique ID of the initiating process was:

`2533274790397065`

### Why It Matters

This unique process identifier allowed the remainder of the hunt to track activity tied to the same PowerShell-driven operator session across process, file, and network telemetry.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 155017.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-8">⚐ <strong>Flag 8: Discovery – Runtime Application Inventory</strong></summary>

### Objective

Identify the process that best demonstrates runtime process enumeration on the host.

### Investigation

Process execution telemetry was reviewed for `tasklist`, the native Windows utility used to enumerate currently running processes.

### KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("tasklist")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

### Finding

The file name of the process performing runtime enumeration was:

`tasklist.exe`

### Why It Matters

`tasklist /v` gives an operator a snapshot of active processes, sessions, and window titles, helping identify security tools, business applications, and targets for avoidance or follow-on collection.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 155300.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-9">⚐ <strong>Flag 9: Discovery – Privilege Surface Check</strong></summary>

### Objective

Identify the timestamp of the first privilege enumeration attempt.

### Investigation

Because the hint pointed toward `whoami`, the investigation filtered process events for `whoami`, `whoami /priv`, and `whoami /groups`, then sorted ascending to identify the first occurrence.

### KQL Query Used

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("whoami", "whoami /priv", "whoami /groups", "net user")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

### Finding

The first privilege-check attempt occurred at:

`2025-10-09T12:52:14.3135459Z`

### Why It Matters

Privilege mapping informs whether an operator can proceed directly with collection and persistence or must pursue elevation. This was a key step in understanding access boundaries on the host.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 155300.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-10">⚐ <strong>Flag 10: Network Validation – First Outbound Destination</strong></summary>

### Objective

Identify the first outbound destination contacted by the operator’s tracked session.

### Investigation

Using the previously established `InitiatingProcessUniqueId`, the investigation pivoted into `DeviceNetworkEvents` to isolate network activity tied to the same PowerShell session.

### KQL Query Used

```kql
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where InitiatingProcessUniqueId == 2533274790397065
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### Finding

The first outbound destination contacted was:

`www.msftconnecttest.com`

### Why It Matters

This connection validated outbound HTTP connectivity and confirmed that the host could reach the internet. Even though the destination is benign, the operator’s use of it demonstrated egress path testing before simulated transfer activity.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 160348.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-11">⚐ <strong>Flag 11: Collection – Bundling / Staging Artifact</strong></summary>

### Objective

Identify where the staged artifact was first dropped for transfer preparation.

### Investigation

The hunt pivoted into `DeviceFileEvents`, again scoped to the same tracked PowerShell session. Reviewing file creation and modification activity revealed staging behavior associated with a ZIP archive.

### KQL Query Used

```kql
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:45:00Z) .. datetime(2025-10-09T13:10:00Z))
| where InitiatingProcessUniqueId == 2533274790397065
| project TimeGenerated, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### Finding

The staged archive artifact identified in telemetry was:

`C:\Users\Public\ReconArtifacts.zip`

### Why It Matters

The creation of a ZIP archive demonstrates local staging behavior, a practical preparation step before exfiltration. Consolidating files into one package reduces transfer complexity and clearly signals collection intent.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 161005.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-12">⚐ <strong>Flag 12: Exfiltration – Last Unusual Outbound Connection</strong></summary>

### Objective

Identify the IP address of the final unusual outbound connection made by the operator session.

### Investigation

The same scoped `DeviceNetworkEvents` view was used to evaluate the full sequence of outbound connections tied to the PowerShell session. The latest unusual outbound connection was then identified chronologically.

### KQL Query Used

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessUniqueId == 2533274790397065
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| order by TimeGenerated asc
```

### Finding

The final unusual outbound connection resolved to:

`100.29.147.161`

### Why It Matters

This IP corresponded to `httpbin.org`, a public service commonly used in labs to simulate HTTP requests and uploads. Its presence demonstrates explicit outbound transfer testing and confirms exfiltration intent.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 161844.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-13">⚐ <strong>Flag 13: Persistence – Scheduled Re-Execution Task</strong></summary>

### Objective

Identify the scheduled task name created to re-run the tooling at user logon.

### Investigation

The operator session was examined for executions of `schtasks.exe`. The resulting task creation command clearly showed a logon-triggered persistence mechanism.

### KQL Query Used

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessUniqueId == 2533274790397065
| where ProcessCommandLine has "schtasks"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

### Finding

The task name created for persistence was:

`SupportToolUpdater`

### Why It Matters

A scheduled task configured with `/SC ONLOGON` ensures the malicious or suspicious script is re-executed every time a user signs in, giving the operator durable re-entry.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 163012.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-14">⚐ <strong>Flag 14: Persistence – Autorun Fallback Registry Value</strong></summary>

### Objective

Identify the Run key registry value added as a backup persistence mechanism.

### Investigation

User-scope autorun persistence was investigated through `DeviceRegistryEvents`, focusing on registry writes occurring after the primary persistence step. The relevant Run key value exposed the fallback autorun entry.

### KQL Query Used

```kql
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-15))
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, ActionType
| order by TimeGenerated asc
```

### Finding

The registry value name added for fallback persistence was:

`RemoteAssistUpdater`

### Why It Matters

Run key persistence in user scope provides a second execution path if the scheduled task is removed or fails. Redundant persistence increases resilience and complicates remediation.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 163741.png" width="700">
</p>

</details>

---

<details>
<summary id="flag-15">⚐ <strong>Flag 15: Masquerading – Narrative / Cover Artifact</strong></summary>

### Objective

Identify the explanatory artifact left behind to frame or justify suspicious activity.

### Investigation

The final step was to locate text, link, or log artifacts created immediately after persistence activity. File telemetry revealed the creation and modification of a support-themed log file, along with a shortcut in the user’s Recent items, indicating the actor opened it.

### KQL Query Used

```kql
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:58:17.4364257Z) .. datetime(2025-10-15))
| where ActionType == "FileCreated" 
    or ActionType == "FileModified"
| where FileName endswith ".txt" 
    or FileName endswith ".lnk" 
    or FileName endswith ".log"
| project TimeGenerated, FileName, ActionType, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

### Finding

The cover artifact left behind was:

`SupportChat_log.lnk`

### Why It Matters

A support-themed log artifact is a classic narrative device meant to make malicious activity appear like benign troubleshooting or support work. The `.lnk` creation in the Recent folder also indicates the file was opened, matching the scenario hint.

### Evidence

<p align="left">
  <img src="assets/Screenshot 2026-03-05 163937.png" width="700">
</p>

</details>

---

## Detection Gaps & Recommendations

### Observed Gaps

* PowerShell execution from a user Downloads directory was not blocked or alerted early enough.
* Discovery activity using native utilities such as `whoami`, `quser`, `qwinsta`, `tasklist`, and `wmic` occurred in a concentrated burst without clear preventive interruption.
* Outbound network validation and transfer testing to public services were allowed from the same suspicious PowerShell session.
* Staging activity involving a ZIP archive in a broadly accessible location was not immediately detected.
* Persistence through both `schtasks.exe` and a user-scope Run key was established within minutes of initial execution.
* Narrative or cover-artifact creation in the user Downloads area could plausibly reduce user suspicion and delay reporting.

### Recommendations

* Alert on PowerShell launched from user-writable locations, especially Downloads, with `-ExecutionPolicy Bypass`, `-NoProfile`, or hidden/non-interactive execution patterns.
* Correlate short discovery bursts involving `whoami`, `wmic`, `quser`, `qwinsta`, `query session`, and `tasklist` from the same parent process.
* Monitor for ZIP archive creation in `C:\Users\Public\` and other common staging paths when preceded by discovery commands.
* Alert on outbound connectivity tests and HTTP/HTTPS requests from suspicious PowerShell sessions to public utility endpoints.
* Monitor and block suspicious scheduled task creation with logon triggers and PowerShell-based task actions.
* Monitor `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for newly created autorun values referencing PowerShell or previously observed tooling.
* Flag creation of support-themed or helpdesk-themed artifacts near malicious execution chains as possible masquerading or narrative control.

## Final Assessment

This intrusion demonstrates a deliberate, low-noise operator workflow centered on a PowerShell script disguised as a support utility. The actor progressed from execution into discovery, privilege and session mapping, storage assessment, runtime process inventory, outbound connectivity testing, local staging, simulated upload activity, and persistence establishment in under a single user session. The addition of both scheduled task persistence and a Run key fallback indicates an intent to survive beyond the initial interaction, while the support-themed log artifact suggests an effort to reduce suspicion and reframe the activity as legitimate. Defender telemetry was sufficient to reconstruct the full sequence, but the environment allowed the attack to proceed through multiple phases without interruption. Stronger controls around script execution, suspicious native utility chaining, outbound transfer validation, and persistence creation would materially reduce risk.

## Analyst Notes

* Hunt performed in **Azure Log Analytics Workspace** using Microsoft Defender for Endpoint telemetry
* Investigation correlated process, file, registry, and network events back to a single `InitiatingProcessUniqueId`
* Screenshots should be stored in the `assets` folder using your standard naming convention
* Report structure is designed for portfolio use and SOC interview discussion
* Techniques align cleanly to a discovery → staging → exfiltration test → persistence chain
