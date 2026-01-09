#  Threat Event: <THREAT NAME>
**<Short, descriptive subtitle of the threat>**

---

## Overview

This document defines a threat event designed to intentionally generate endpoint telemetry and indicators of compromise (IoCs) for threat hunting and detection validation. The activity outlined below represents simulated adversary behavior executed in a controlled lab environment.

This threat event serves as the **event creation phase** and is intended to be followed by a separate threat hunting investigation using collected telemetry.

---

## Steps the “Bad Actor” Took to Create Logs and IoCs

1. **Prepare the environment**
   - Provision a test endpoint (virtual or physical) in a controlled environment
   - Ensure endpoint telemetry is enabled and actively reporting

2. **Download the required tooling**
   - Example:
     ```
     <URL or source of tool>
     ```

3. **Install the tool (if applicable)**
   - Example silent install:
     ```cmd
     <installer-name> /S
     ```

4. **Execute the tool**
   - Launch the application from disk
   - Allow all supporting processes/services to start

5. **Generate network activity**
   - Perform actions that cause outbound connections
   - Browse benign sites or trigger expected traffic patterns
   - ⚠️ *Note: Visiting normal sites is sufficient to generate telemetry*

6. **Create user artifacts**
   - Example:
     - Create a file named:
       ```
       <artifact-name>.txt
       ```
     - Add fictitious or placeholder content

7. **Cleanup activity**
   - Delete the created artifact(s)
   - Close the application

---

## Tables Used to Detect IoCs

### DeviceFileEvents

| Parameter | Description |
|---------|------------|
| **Name** | DeviceFileEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose** | Detects file downloads, installations, file creation, modification, and deletion related to the threat activity |

---

### DeviceProcessEvents

| Parameter | Description |
|---------|------------|
| **Name** | DeviceProcessEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose** | Detects execution of installers, binaries, services, and application processes |

---

### DeviceNetworkEvents

| Parameter | Description |
|---------|------------|
| **Name** | DeviceNetworkEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose** | Detects outbound network connections, remote IPs, ports, and URLs associated with the threat |

---

## Related Detection Queries

```kql
// Detect suspicious file downloads
DeviceFileEvents
| where FileName contains "<keyword>"
| order by Timestamp asc

// Detect installer or binary execution
DeviceProcessEvents
| where ProcessCommandLine contains "<binary-name>"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Detect tool execution
DeviceProcessEvents
| where FileName has_any ("<binary1>", "<binary2>")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

// Detect related network activity
DeviceNetworkEvents
| where InitiatingProcessFileName in ("<binary1>", "<binary2>")
| where RemotePort in (<port-list>)
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc

// Detect user artifact creation or deletion
DeviceFileEvents
| where FileName contains "<artifact-name>"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
````

---

## Metadata

**Created By:**

* **Author Name:** <Your Name>
* **Author Contact:** <GitHub / LinkedIn (optional)>
* **Date:** <Date>

**Validated By:**

* **Reviewer Name:**
* **Reviewer Contact:**
* **Validation Date:**

---

## Additional Notes

* This threat event was created for educational and detection validation purposes.
* All activity was performed in a controlled lab environment.

---

## Revision History

| Version | Changes       | Date   | Modified By |
| ------- | ------------- | ------ | ----------- |
| 1.0     | Initial draft | <Date> | <Name>      |
