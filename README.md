# LOGN Pacific Cyber Range Automation

This repository contains automation used inside the LOGN Pacific Cyber Range to create, detect, remediate, and validate security weaknesses across Windows and Linux systems.

The scripts in this repo are not standalone tools. They are building blocks used to simulate real enterprise security workflows such as vulnerability scanning, remediation validation, detection engineering, and compliance testing.

---

## Purpose

This repository exists to make security state changes:

- repeatable
- observable
- reversible
- measurable

Rather than manually misconfiguring systems or fixing findings by hand, these scripts allow controlled security posture changes that can be scanned, detected, investigated, and verified.

The focus is not exploitation.  
The focus is detection, response, and remediation.

---

## How This Repo Is Used

Scripts in this repository are executed inside Azure-hosted lab virtual machines as part of structured security exercises.

Typical workflow:

1. Introduce a controlled weakness
2. Scan or detect the change using enterprise tooling
3. Investigate the signal or finding
4. Remediate using automation
5. Re-scan to confirm resolution

This mirrors how vulnerabilities are handled in real production environments, without relying on unsafe ad-hoc configuration changes.

---

## Types of Automation

### Security Weakening

Scripts used to intentionally reduce security posture for testing and detection purposes.

Examples include:

- enabling legacy services such as SMBv1 or Telnet
- installing outdated or vulnerable software
- weakening authentication or authorization paths
- enabling deprecated TLS or cipher configurations
- modifying sensitive Linux permissions

These scripts are used to generate realistic findings for scanners, EDR tools, and SIEM pipelines.

---

### Security Remediation

Scripts used to restore secure configurations and validate remediation workflows.

Examples include:

- removing vulnerable software
- disabling insecure protocols and services
- enforcing modern TLS and cipher standards
- restoring secure permissions
- patching operating systems
- automating reboot and validation steps

Remediation scripts are designed to be idempotent and auditable where possible.

---

## Cyber Range Context

This repository supports a live cyber range environment built in Azure.

It is used alongside:

- authenticated vulnerability scanning
- endpoint detection and response tooling
- log aggregation and investigation
- compliance-oriented testing inspired by STIG and CIS guidance

The repository evolves as new labs, detections, and remediation scenarios are added.

---

## Tooling and Platforms

- PowerShell for Windows automation
- Bash for Linux automation
- Azure virtual machines
- Tenable Vulnerability Management
- Microsoft Defender for Endpoint
- Microsoft Sentinel
- MITRE ATT&CK–aligned detection logic

---

## Safety Notice

This repository is intended for training and authorized research only.

Scripts may intentionally weaken system security.  
They should only be executed in controlled lab environments on systems you own or are authorized to test.

You are responsible for how this code is used.
