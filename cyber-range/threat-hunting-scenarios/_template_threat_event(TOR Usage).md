# Threat Event: Unauthorized TOR Usage

This threat event was created as part of an individual Cyber Range internship project to simulate unauthorized TOR Browser usage on an enterprise endpoint. The goal of this scenario is to intentionally generate endpoint telemetry related to TOR installation, execution, and anonymized network activity so that it can later be detected and analyzed through a structured threat hunting exercise using Microsoft Defender for Endpoint (MDE).

This document represents the “bad actor” phase of the exercise and serves as the foundation for subsequent threat hunting and investigation.

---

## Lab Environment

### Azure Virtual Machine Configuration

| Component           | Details                                     |
| ------------------- | ------------------------------------------- |
| **VM Name**         | `threat-hunt-lab`                           |
| **OS Image**        | Windows 11 Pro 25H2                         |
| **Region**          | East US 2                                   |
| **VM Size**         | Standard DS1 v2 (1 vCPU, 3.5 GiB RAM)       |
| **Security Type**   | Trusted Launch (Secure Boot + vTPM enabled) |
| **Virtual Network** | Cyber-Range-VNet                            |
| **Subnet**          | Cyber-Range-Subnet                          |
| **Public IP**       | 172.203.70.40                               |
| **Private IP**      | 10.0.0.181                                  |
| **Disk Encryption** | Disabled                                    |
| **Auto-Shutdown**   | Not enabled                                 |
| **VM Extensions**   | AzurePolicyforWindows                       |

---

## Endpoint Onboarding & Telemetry Validation

1. The virtual machine was onboarded to Microsoft Defender for Endpoint (MDE).
2. Telemetry ingestion was validated using Advanced Hunting queries to confirm that the endpoint was actively reporting data.

<p align="left">
  <img src="screenshots/Screenshot 2025-11-21 082048.png" width="750">
  <img src="screenshots/Screenshot 2026-01-08 142244.png" width="750">
  <img src="screenshots/Screenshot 2026-01-08 143742.png" width="750">
</p>

* VM onboarded to MDE
* Telemetry confirmed via `DeviceInfo`

---

## Threat Simulation – Bad Actor Activity

The following actions were intentionally performed to generate TOR-related logs and indicators of compromise (IoCs):

### 1️⃣ TOR Browser Download

The TOR Browser portable installer was downloaded from the official TOR Project website:

🔗 [https://www.torproject.org/download/](https://www.torproject.org/download/)

---

### 2️⃣ Silent Installation of TOR Browser

The TOR Browser portable installer was executed using a silent installation switch to simulate covert software deployment:

```cmd
tor-browser-windows-x86_64-portable-15.0.3.exe /S
```

<p align="left">
  <img src="screenshots/Screenshot 2026-01-09 143014.png" width="750">
</p>

---

### 3️⃣ TOR Browser Execution

The TOR Browser was launched directly from the extracted folder on the desktop.

<p align="left">
  <img src="screenshots/Screenshot 2026-01-09 064530.png" width="750">
  <img src="screenshots/Screenshot 2026-01-09 064704.png" width="750">
</p>

* TOR Browser launch
* TOR connection screen

---

### 4️⃣ TOR Network Activity

Once connected to the TOR network, browsing activity was performed to generate anonymized network traffic. Example sites visited include:

* [https://duckduckgo.com](https://duckduckgo.com)
* [https://wikipedia.org](https://wikipedia.org)
* [https://check.torproject.org](https://check.torproject.org)

<p align="left">
  <img src="screenshots/Screenshot 2026-01-09 065018.png" width="750">
  <img src="screenshots/Screenshot 2026-01-09 065208.png" width="750">
  <img src="screenshots/Screenshot 2026-01-09 065311.png" width="750">
</p>

* TOR browser browsing activity
* TOR connectivity confirmation

---

### 5️⃣ User Artifact Creation

A text file named `tor-shopping-list.txt` was created on the desktop containing fictitious illicit items to simulate user note-taking activity associated with TOR usage.

📸 *Screenshot reference:* File contents

---

### 6️⃣ Artifact Cleanup

The `tor-shopping-list.txt` file was deleted to generate additional file system activity related to cleanup behavior.

---

## 🔎 Tables Used to Detect Indicators of Compromise (IoCs)

### DeviceFileEvents

**Info:**
[https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)

**Purpose:**
Used to detect TOR installer downloads, TOR Browser file extraction, and creation or deletion of the `tor-shopping-list.txt` file.

---

### DeviceProcessEvents

**Info:**
[https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)

**Purpose:**
Used to detect silent installation of TOR Browser as well as execution of TOR-related processes (`tor.exe`, `firefox.exe`).

---

### DeviceNetworkEvents

**Info:**
[https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)

**Purpose:**
Used to detect TOR-related network activity, specifically anonymized connections initiated by `tor.exe` and `firefox.exe` over ports commonly associated with the TOR network (e.g., 9000–9150 range).

---

## 🧪 Related Detection Queries

### Detect TOR Browser Installer Download

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where FileName startswith "tor-browser-windows-x86_64-portable"
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
```

---

### Detect Silent TOR Browser Installation

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where AccountName == "awl4114awl"
| where ProcessCommandLine has "tor-browser-windows-x86_64-portable-15.0.3.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, SHA256
```

---

### Detect TOR Browser Files Present on Disk

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
```

---

### Detect TOR Browser or Service Execution

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where AccountName == "awl4114awl"
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine
```

---

### Detect TOR Network Activity

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in (9000, 9001, 9005, 9100, 9150, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```

---

### Detect TOR Shopping List Creation or Deletion

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where FileName contains "tor-shopping-list.txt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

---

## 📄 Metadata

**Created By:**
Author Name: **Jordan Calvert**
Author Contact: *(optional – GitHub or LinkedIn)*
Date: **January 9, 2026**

**Validated By:**
Reviewer Name:
Reviewer Contact:
Validation Date:

---

## 📝 Additional Notes

This threat event was created to support an individual Cyber Range internship project focused on simulating unauthorized TOR Browser usage and validating detection and hunting capabilities using Microsoft Defender for Endpoint telemetry.

---

## 🗂️ Revision History

| Version | Changes                                              | Date            | Modified By    |
| ------- | ---------------------------------------------------- | --------------- | -------------- |
| 1.0     | Initial draft adapted for individual lab environment | January 9, 2026 | Jordan Calvert |
