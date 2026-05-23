# Cyber Detection Home Lab
**SOC Analyst Portfolio | SIEM, Threat Detection, and Active Directory Attack Simulation**

**Certifications:** SSCP | CySA+ | PenTest+ | Security+ | Network+ | A+  
**Education:** B.S. Cybersecurity and Information Assurance, Western Governors University  
**Status:** Active and ongoing | Week 3 of 8 complete | Last updated: May 2026

---

## What This Repository Is

This repository documents a hands-on home lab I built to develop real-world SOC analyst skills through attack simulation and SIEM-based threat detection. Rather than following tutorials, I built a production-style segmented network, deployed enterprise tools, and practiced the full detection cycle: simulate an attack, generate telemetry, hunt the evidence in Splunk, and document what I found.

The lab mirrors environments I expect to work in as a SOC Analyst. Every detection query in this repository has been tested against real attack simulations using Atomic Red Team. Every troubleshooting note represents a real problem I encountered and solved.

---

## Lab Architecture

![Lab Network Diagram](images/networkmap.png)

```
Internet
    |
PFSense Firewall (192.168.40.13/24)
    |
    +-- Active Directory Lab (10.10.10.0/24)
    |       WS01 (10.10.10.1)  - Windows Workstation / Atomic Red Team
    |       WS02 (10.10.10.2)  - Windows Workstation / Victim machine
    |       DC01 (10.10.10.3)  - Windows Server / Domain Controller (lab.local)
    |
    +-- SOC Lab (10.10.20.0/24)
    |       Splunk  (10.10.20.3)  - SIEM / Primary detection platform
    |       Nessus  (10.10.20.6)  - Vulnerability scanner
    |       AtomicRed (10.10.20.4) - Remote attack simulation
    |       Wazuh   (10.10.20.5)  - Host-based IDS / EDR
    |
    +-- Vulnerable Machines (10.10.30.0/24)
    |       Metasploitable 2 (10.10.30.1)
    |       DVWA             (10.10.30.2)
    |       WebGoat          (10.10.30.3)
    |
    +-- Attackers (10.10.40.0/24)
            Kali Linux  (10.10.40.1)
            Parrot OS   (10.10.40.2)
```

---

## Skills Demonstrated

**SIEM and Detection Engineering**
- Deployed and configured Splunk with Universal Forwarders across multiple endpoints
- Wrote and tested production-ready SPL detection queries for 6 MITRE ATT&CK techniques
- Built a 5-panel AD Health Monitor dashboard with real-time threat visibility
- Configured Splunk alerting with throttling and severity levels
- Resolved real-world ingestion issues including index routing, clock skew, and field extraction

**Windows Security and Event Log Analysis**
- Analyzed and documented 15+ Windows Security Event IDs with detection context
- Configured domain-wide audit policy via GPO for comprehensive log coverage
- Deployed and configured Sysmon on all endpoints for enhanced telemetry
- Correlated multi-event attack chains (e.g., 4720 account creation + 4732 privilege escalation)
- Extracted meaning from multivalue SPL fields using mvindex and eval

**Active Directory Attack Detection**
- Detected and investigated Kerberoasting (T1558.003) via EventCode 4769 + RC4 tickets
- Detected lateral movement (T1021.002) via Logon_Type=3 network logons
- Detected brute force credential attacks (T1110.001) with Sub_Status analysis
- Detected persistence via scheduled tasks (T1053.005) via EventCode 4698
- Detected backdoor account creation and privilege escalation (T1136.001) via correlated 4720+4732

**Lab Infrastructure and Engineering**
- Designed and built a segmented four-subnet lab network
- Configured PFSense firewall for inter-segment routing
- Built NTP hierarchy (PFSense to DC01 to workstations) to solve log timing issues
- Configured Restricted Groups GPO for local administrator management
- Troubleshot and resolved 13+ documented technical issues end to end

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic | Detected | Detection Method |
|---|---|---|---|---|
| T1059.001 | PowerShell Execution | Execution | Yes | Sysmon EventCode 1, EventCode 4688 |
| T1110.001 | Brute Force | Credential Access | Yes | EventCode 4625 with bucket analysis |
| T1136.001 | Create Local Account | Persistence | Yes | EventCode 4720 correlated with 4732 |
| T1558.003 | Kerberoasting | Credential Access | Yes | EventCode 4769 + Ticket_Encryption_Type=0x17 |
| T1021.002 | SMB Lateral Movement | Lateral Movement | Yes | EventCode 4624 Logon_Type=3 |
| T1053.005 | Scheduled Task Persistence | Persistence | Yes | EventCode 4698 |
| T1078 | BloodHound AD Enumeration | Discovery | Observed | Mass Logon_Type=3 events on DC01 |
| T1003.001 | LSASS Memory Dump | Credential Access | In Progress | Requires Sysmon EventCode 10 config (Week 6) |
| T1048.003 | DNS Exfiltration | Exfiltration | Planned | Week 4+ |

---

## Detection Queries

All tested SPL queries are in the [queries/](queries/) folder, organized by technique. Here are selected examples.

**Kerberoasting Detection**
```splunk
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| table _time, host, Account_Name, Service_Name, Ticket_Encryption_Type
| sort -_time
```

**Brute Force with Time Bucketing**
```splunk
index=windows EventCode=4625
| eval user=mvindex(Account_Name,1)
| bucket _time span=60s
| stats count by _time, user, Source_Network_Address, host
| where count >= 5
| sort -count
```

**Backdoor Account + Privilege Escalation Correlation**
```splunk
index=windows (EventCode=4720 OR EventCode=4732)
| eval Computer=coalesce(Computer, host)
| eval EventType=case(EventCode=4720, "Account Created", EventCode=4732, "Added to Administrators")
| table _time, Computer, EventCode, EventType, Account_Name, SAM_Account_Name
| sort _time
```

**Lateral Movement Indicator**
```splunk
index=windows EventCode=4624
| stats dc(host) as machines_accessed, values(host) as hosts by Account_Name
| where machines_accessed > 1
| sort -machines_accessed
```

See [queries/](queries/) for the full library with documentation.

---

## Dashboard

The AD Health Monitor dashboard provides real-time visibility across five detection categories.

![Active Directory Health Monitor](images/ad_dashboard.png)

---

## Repository Structure

```
cyber-detection-lab/
|
+-- README.md                    <- You are here
+-- docs/
|   +-- lab-context.md           <- Network topology, VM inventory, tool reference
|   +-- progress-tracker.md      <- 8-week curriculum progress and session logs
|   +-- cheatsheet.md            <- Event ID reference, SPL library, troubleshooting notes
|
+-- queries/
|   +-- foundational.spl         <- First-look and baseline queries
|   +-- brute-force.spl          <- T1110.001 credential attack detection
|   +-- account-lifecycle.spl    <- T1136.001 backdoor account detection
|   +-- kerberoasting.spl        <- T1558.003 Kerberos attack detection
|   +-- lateral-movement.spl     <- T1021.002 network logon analysis
|   +-- persistence.spl          <- T1053.005 scheduled task detection
|   +-- powershell.spl           <- T1059.001 PowerShell execution detection
|
+-- images/
|   +-- dashboard-screenshot.png <- AD Health Monitor dashboard (add your screenshot here)
|   +-- network-diagram.png      <- Lab architecture diagram (optional)
|
+-- .gitignore                   <- Protects credentials and VM files
```

---

## Learning Progress

| Week | Topic | Status | Confidence |
|---|---|---|---|
| 1 | Lab Setup and Splunk Fundamentals | Complete | 3/10 |
| 2 | Windows Event Log Analysis | Complete | 4/10 |
| 3 | Active Directory Attack Detection | Complete | 5/10 |
| 4 | Linux Syslog and Auditd | Not started | |
| 5 | Network Detection with PFSense and DNS | Not started | |
| 6 | Threat Hunting with MITRE ATT&CK | Not started | |
| 7 | SIEM Alerting and Correlation Rules | Not started | |
| 8 | Capstone: Full Attack Chain Detection | Not started | |

**Total lab hours logged:** 16.5 hours across 4 sessions

---

## Tools and Technologies

| Category | Tool |
|---|---|
| SIEM | Splunk Enterprise |
| Telemetry | Sysmon, Windows Universal Forwarder |
| Attack Simulation | Atomic Red Team (MITRE ATT&CK mapped) |
| Active Directory | Windows Server 2019, lab.local domain |
| Vulnerability Scanning | Nessus |
| EDR | Wazuh |
| Offensive Platforms | Kali Linux, Parrot OS |
| Firewall | PFSense |
| Query Language | SPL (Splunk Processing Language) |
| Framework | MITRE ATT&CK |

---

## Documentation

Full documentation lives in the [docs/](docs/) folder:

- **[Lab Context](docs/lab-context.md)** - Complete network topology, VM inventory, and tool reference
- **[Progress Tracker](docs/progress-tracker.md)** - Curriculum map, session logs, and confidence scores
- **[Cheatsheet](docs/cheatsheet.md)** - Windows Event ID reference, SPL query library, Sysmon reference, and troubleshooting notes

---

## About Me

I am a cybersecurity graduate from Western Governors University with a B.S. in Cybersecurity and Information Assurance, currently building hands-on SOC analyst skills through this lab while seeking my first role in security operations.

**Certifications:** SSCP | CySA+ | PenTest+ | Security+ | Network+ | A+

I built this lab because I believe the gap between certification knowledge and real detection work is best closed through doing. This repository is the evidence.

---

## Connect

If you are a recruiter, hiring manager, or fellow security practitioner, feel free to reach out.

[LinkedIn](https://www.linkedin/in/vic1101) | [GitHub](https://www.github.com/netcur10s) | [Email](mailto:v.echevarria@proton.me)

*Replace the bracketed links above with your actual contact information before publishing.*
