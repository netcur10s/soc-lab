# Cyber Detection Home Lab

# Lab Context & Reference Document

*Doc 1 of 3  |  Last updated: May 20, 2026*

## 1. Lab Overview

This document is the permanent reference for your home lab environment. It is uploaded into your Claude Project so that Claude can read your setup at the start of every session without you needing to re-explain it.

**Purpose:** Build real-world SOC analyst and cyber detection skills through hands-on attack simulation, log analysis, and Splunk-based threat hunting.

## 2. Network Topology

Your lab is segmented into four isolated subnets connected through a PFSense firewall, plus internet access via 192.168.40.13/24.

| **Segment** | **Subnet** | **Purpose** |
| --- | --- | --- |
| Active Directory Lab | 10.10.10.0/24 | Windows domain environment — primary victim network |
| SOC Lab | 10.10.20.0/24 | Detection & analysis tools — Splunk, Nessus, Wazuh, AtomicRed |
| Vulnerable Machines | 10.10.30.0/24 | Intentionally vulnerable targets for exploitation practice |
| Attackers | 10.10.40.0/24 | Offensive platforms — Kali Linux and Parrot OS |
| WAN / Firewall | 192.168.40.13/24 | PFSense — internet gateway and inter-segment routing |

## 3. Virtual Machine Inventory

### 3.1 Active Directory Lab — 10.10.10.0/24

| **Hostname** | **IP Address** | **OS / Role** | **Notes** |
| --- | --- | --- | --- |
| WS01 | 10.10.10.1/24 | Windows Workstation | Atomic Red Team installed locally — use for local attack simulation |
| WS02 | 10.10.10.2/24 | Windows Workstation | Standard endpoint — victim machine |
| DC01 | 10.10.10.3/24 | Windows Server (Domain Controller) | Active Directory domain controller for lab.local domain |

### 3.2 SOC Lab — 10.10.20.0/24

| **Tool** | **IP Address** | **Role** | **Notes** |
| --- | --- | --- | --- |
| Splunk | 10.10.20.3/24 | SIEM — primary detection platform | Main tool for log ingestion, search, alerting, and dashboards |
| Nessus | 10.10.20.6/24 | Vulnerability scanner | Use to scan vulnerable machines and understand attack surface |
| AtomicRed (remote) | 10.10.20.4/24 | Remote attack simulation endpoint | Use once comfortable with ART — for remote attack chains |
| Wazuh | 10.10.20.5/24 | Host-based IDS / EDR | Endpoint detection and log forwarding complement to Splunk |

### 3.3 Vulnerable Machines — 10.10.30.0/24

| **Machine** | **IP Address** | **Type** | **Notes** |
| --- | --- | --- | --- |
| Metasploitable 2 | 10.10.30.1/24 | Linux — intentionally vulnerable | Classic exploitation target — great for Metasploit practice |
| DVWA | 10.10.30.2/24 | Web app — intentionally vulnerable | Damn Vulnerable Web App — SQL injection, XSS, file upload, etc. |
| Webgoat | 10.10.30.3/24 | Web app — OWASP training | OWASP WebGoat — structured web vulnerability lessons |

### 3.4 Attackers — 10.10.40.0/24

| **Machine** | **IP Address** | **OS** | **Notes** |
| --- | --- | --- | --- |
| Kali Linux | 10.10.40.1/24 | Kali Linux | Primary offensive platform — Metasploit, Nmap, Burp Suite, etc. |
| Parrot OS | 10.10.40.2/24 | Parrot Security OS | Alternative offensive platform — privacy and pentesting tools |

## 4. Firewall

| **Device** | **WAN IP** | **LAN Gateway** | **Role** |
| --- | --- | --- | --- |
| PFSense | 192.168.40.13/24 | 10.10.10.254/24 | Routes traffic between all four segments and to the internet. |

## 5. Atomic Red Team Setup

| **Location** | **IP** | **Use case** | **When to use** |
| --- | --- | --- | --- |
| WS01 (local) | 10.10.10.1 | Local attack simulation on the endpoint itself | NOW — use this to generate telemetry and practice detecting attacks in Splunk |
| AtomicRed VM (remote) | 10.10.20.4 | Remote attack orchestration targeting AD/Vulnerable segments | LATER — once familiar with ART syntax and Splunk detection workflow |

📌 Start with WS01 local ART. Run a technique, then find it in Splunk. This is the core learning loop.

## 6. Log Sources & Splunk Ingestion

| **Log Source** | **Machine** | **Method** | **Status** |
| --- | --- | --- | --- |
| Windows Security Events (Event ID logs) | WS01, WS02, DC01 | Splunk Universal Forwarder | ✓ Configured |
| Sysmon (enhanced process/network telemetry) | WS01, WS02 | Splunk Universal Forwarder | ✓ Configured |
| Active Directory logs | DC01 | Splunk Universal Forwarder | ✓ Configured |
| Wazuh agent events | Wazuh (10.10.20.5) | Wazuh → Splunk integration | [ ] Configure |
| PFSense firewall logs | PFSense | Syslog → Splunk | [ ] Configure |
| Metasploitable / Linux syslog | 10.10.30.1 | Syslog → Splunk | [ ] Configure |

## 7. Installed Tools Reference

| **Tool** | **Location** | **Purpose** |
| --- | --- | --- |
| Splunk | 10.10.20.3 | SIEM — all log search, alerting, dashboards |
| Nessus | 10.10.20.6 | Vulnerability scanning |
| Wazuh | 10.10.20.5 | HIDS / EDR — endpoint detection and log forwarding |
| Atomic Red Team | WS01 + 10.10.20.4 | MITRE ATT&CK-mapped attack simulation |
| Metasploit | Kali 10.10.40.1 | Exploitation framework |
| Nmap | Kali 10.10.40.1 | Network scanning and discovery |
| Burp Suite | Kali 10.10.40.1 | Web application testing proxy |
| Metasploitable 2 | 10.10.30.1 | Vulnerable Linux target for exploitation |
| DVWA | 10.10.30.2 | Vulnerable web app for web attack practice |
| WebGoat | 10.10.30.3 | OWASP web vulnerability training |

## 8. Session Notes

### May 19, 2026

- jsmith requires Event Log Readers group membership on DC01 for Splunk forwarder to read Security event logs

- svc_sql service account created in AD as Kerberoasting target

    SPN: MSSQLSvc/DC-01.lab.local:1433

    Encryption forced to RC4 only (msDS-SupportedEncryptionTypes = 0x4)

- Full audit policy configured via Default Domain Policy GPO on DC01:

    Kerberos Service Ticket Operations: Success and Failure

    Kerberos Authentication Service: Success and Failure

    Credential Validation: Success and Failure

    User Account Management: Success and Failure

    Security Group Management: Success and Failure

    Computer Account Management: Success and Failure

    Directory Service Access: Success and Failure

    Process Creation: Success

    Audit Policy Change: Success and Failure

- index=windows contains all AD machine logs (WS01, WS02, DC-01)

- AD Health Monitor dashboard built in Splunk with 5 panels

### May 20, 2026

- Enabled "Audit Other Object Access Events" via GPO for EventCode 4698 detection

    Path: Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Object Access → Audit Other Object Access Events

    Configured: Success and Failure

- Ran ART T1053.005-2 successfully — created scheduled task named "spawn" on WS01

- EventCode 4698 now logging to Splunk after audit policy change + gpupdate /force

- AD Health Monitor dashboard expanded to 5 panels:
    1. Failed Logons Overtime
    2. Network Logons (Lateral Movement)
    3. New Accounts Created
    4. Kerberoasting Attempts (RC4 Tickets)
    5. Scheduled Tasks Created (new)

- Attempted T1003.001-1 (ProcDump) — failed with "Access is denied" (expected for protected process)

- Ran T1003.001-2 (comsvcs.dll method) successfully — LSASS dump completed but no Sysmon telemetry

- Root cause: Sysmon EventCode 10 (Process Access) not configured or too restrictive by default

- LSASS detection requires explicit Sysmon config for TargetImage=lsass.exe — revisit in Week 6 when tuning Sysmon

- Dashboard field name typos fixed (Account_Name, Service_Name, Who_Created) — no mvindex needed, just spelling errors
