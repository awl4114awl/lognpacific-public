# 🚀 LOGN Pacific — Automation & Vulnerability Scripts

![PowerShell](https://img.shields.io/badge/PowerShell-Automation-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Automation-333?style=for-the-badge\&logo=gnubash)
![Windows](https://img.shields.io/badge/Windows-Security_Hardening-0078D4?style=for-the-badge\&logo=windows)
![Linux](https://img.shields.io/badge/Linux-Security_Hardening-FCC624?style=for-the-badge\&logo=linux\&logoColor=black)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK_Based-DC143C?style=for-the-badge)

---

## 🪟 Overview

This repository contains a collection of **PowerShell** and **Bash** automation scripts used throughout the **LOGN Pacific Cyber Range** environment.
These scripts support:

* **Vulnerability Creation** (intentionally weakening systems for training exercises)
* **Vulnerability Remediation** (secure configuration + patching)
* **Windows & Linux OS Hardening**
* **Protocol, Cipher, and Feature Toggling**
* **Software-Based Vulnerability Labs (Firefox, 7-Zip, Wireshark, Telnet, OpenSSL, etc.)**

These scripts are used across Azure-hosted Windows and Linux VMs as part of hands-on cybersecurity labs involving Tenable, Microsoft Defender for Endpoint, and real-world enterprise security workflows.

---

## What This Repo Is For

This repository enables repeatable, automated configuration changes such as:

### **Create Vulnerabilities**

Used for:

* Threat detection labs
* Attack simulation
* Vulnerability scanning practice
* Blue team investigation exercises

Examples include:

* Enabling **SMBv1**
* Installing outdated **Firefox** or **OpenSSL**
* Allowing **root SSH login**
* Weakening Linux file permissions (`/etc/passwd`, `/etc/shadow`)
* Enabling insecure **TLS/SSL** protocols (SSL 2.0 / 3.0 / TLS 1.0 / 1.1)
* Downgrading ciphersuites

### **Remediate Vulnerabilities**

Used for:

* Hardening baselines
* Patch validation
* Tenable remediation testing
* Compliance exercises (CIS / STIG-inspired)

Examples include:

* Disabling legacy protocols
* Removing vulnerable software (7-Zip, Wireshark, Firefox)
* Enforcing TLS 1.2
* Re-enabling secure permissions
* Updating/downgrading OpenSSL
* OS patching & reboot automation

---

## 📁 Repository Structure

```
lognpacific-public/
│
├── automation/
│   ├── Firefox-Install.ps1
│   ├── SMBv1-Create-Vulnerability.ps1
│   ├── final-hardening.ps1
│   ├── passwd-Linux-Create-Vulnerability.ps1
│   ├── passwd-Linux-Remediate.ps1
│   ├── remediation-FireFox-uninstall.ps1
│   ├── remediation-SMBv1.ps1
│   ├── remediation-Telnet-Remove.sh
│   ├── remediation-openssl-3.0.5-install.sh
│   ├── remediation-root-password.sh
│   ├── remediation-wireshark-uninstall.ps1
│   ├── root-password-Create-Vulnerability.sh
│   ├── telnet-Create-Vulnerability.sh
│   ├── toggle-guest-account-windows.ps1
│   ├── toggle-insecure-cipher-suites.ps1
│   ├── toggle-secure-cipher-suites.ps1
│   ├── toggle_guest_local_administrators.ps1
│   ├── toggle_protocols.ps1
│   ├── ubuntu-os-update-remediation.sh
│   ├── uninstall-7zip.ps1
│
└── (additional folders/scripts added over time)
```

---

## Technology Used

* **PowerShell 5.1+** (Windows Server 2019/2022/2025)
* **Bash** (Ubuntu / Debian)
* **Azure Virtual Machines**
* **Tenable Vulnerability Management**
* **Microsoft Defender for Endpoint**
* **Microsoft Sentinel**
* **MITRE ATT&CK-aligned detection logic**

These scripts directly support hands-on labs for vulnerability scanning, detection engineering, and blue team cybersecurity workflows.

---

## ⚠️ Ethical & Legal Notice

This repository is for **training and authorized research only**.

Do **NOT**:

* deploy these scripts on systems you do not own
* enable insecure protocols in production
* downgrade security configuration outside a lab

You are fully responsible for how you use this code.
