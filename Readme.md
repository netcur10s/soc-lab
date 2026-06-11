# SOC Analyst Home Lab

**A hands-on cybersecurity detection lab built to develop real-world SOC analyst skills through attack simulation and SIEM-based threat hunting.**

## Project Overview

This repository documents my journey building a **complete detection lab from scratch**, simulating an enterprise environment with Active Directory, vulnerable machines, and a full SIEM stack. The goal: detect real-world attack techniques mapped to the MITRE ATT&CK framework using Splunk, Sysmon, and Atomic Red Team.

**Key Outcome:** Progressing from detection engineering (Weeks 1–5) → threat hunting (Week 6) → automated alerting & incident response (Weeks 7–8).

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

**Network Topology:** 4-subnet segmented environment (PFSense firewall) with Active Directory domain, SIEM infrastructure, vulnerable targets, and offensive platforms.

**Tech Stack:**
- **SIEM:** Splunk Enterprise
- **Endpoint Detection:** Sysmon, auditd
- **Attack Simulation:** Atomic Red Team, Metasploit
- **Network Visibility:** PFSense, Wireshark
- **OS:** Windows Server 2022, Windows 10/11, Ubuntu, Kali Linux

## 8-Week Curriculum

| Week | Topic | Status | 
|---|---|---|
| [**Week 1**](./Week1-Lab-Setup) | Lab Setup & Splunk Fundamentals | ✅ Complete |
| [**Week 2**](./Week2-Windows-Events) | Windows Event Log Analysis | ✅ Complete |
| [**Week 3**](./Week3-Active-Directory) | Active Directory Attack Detection | ✅ Complete |
| [**Week 4**](./Week4-Linux-Syslog) | Linux Syslog & Auditd | ✅ Complete |
| [**Week 5**](./Week5-Network-Detection) | Network Detection (PFSense, DNS) | ✅ Complete |
| [**Week 6**](./Week6-Threat-Hunting) | Threat Hunting with MITRE ATT&CK | ✅ Complete |
| [**Week 7**](./Week7-SIEM-Alerting) | SIEM Alerting & Correlation Rules | 🔜 Next |
| [**Week 8**](./Week8-Capstone) | Capstone: Full Attack Chain Detection | ⏳ Planned |

## MITRE ATT&CK Coverage (Weeks 1–6)

| Technique ID | Technique | Tactic | Detection Method | Status |
|---|---|---|---|---|
| T1059.001 | PowerShell Execution | Execution | Sysmon EventCode 1 | ✅ |
| T1110.001 | Brute Force | Credential Access | EventCode 4625 / SSH auth.log | ✅ |
| T1136.001 | Account Creation | Persistence | EventCode 4720/4732 | ✅ |
| T1558.003 | Kerberoasting | Credential Access | EventCode 4769 (RC4 tickets) | ✅ |
| T1021.002 | SMB Lateral Movement | Lateral Movement | EventCode 4624 Logon_Type=3 | ✅ |
| T1053.005 | Scheduled Task Persistence | Persistence | EventCode 4698 | ✅ |
| T1053.003 | Cron Persistence (Linux) | Persistence | syslog CRON entries | ✅ |
| T1548.003 | Sudo Privilege Escalation | Privilege Escalation | linux_secure COMMAND extraction | ✅ |
| T1003.001 | LSASS Credential Dumping | Credential Access | Sysmon EventCode 10 (GrantedAccess) | ✅ |
| T1048.003 | DNS Exfiltration | Exfiltration | Sysmon EC22 + PFSense correlation | ✅ |
| T1046 | Network Service Discovery | Discovery | PFSense filterlog (port scan) | ✅ |
| T1018 | Remote System Discovery | Discovery | PFSense filterlog (ping sweep) | ✅ |
| T1071.001 | C2 Beaconing | Command and Control | PFSense frequency analysis | ✅ |

## Quick Links

**By Week:**
- [Week 1: Lab Setup](weeks/week1-lab-setup.md) — Forwarders, Sysmon, NTP, audit policy, first detection
- [Week 2: Windows Events](weeks/week2-windows-events.md) — Brute force, account creation, GPO audit policy, Splunk alerts
- [Week 3: Active Directory](weeks/week3-active-directory.md) — Kerberoasting, lateral movement, persistence, 5-panel dashboard
- [Week 4: Linux Syslog](weeks/week4-linux-syslog.md) — SSH brute force, sudo escalation, cron persistence
- [Week 5: Network Detection](weeks/week5-network-detection.md) — PFSense, port scans, host discovery, DNS exfiltration, C2 beaconing
- [Week 6: Threat Hunting](weeks/week6-threat-hunting.md) — 3 hypothesis-driven hunts, behavioral anomaly detection, hunting dashboard
- [Week 7: SIEM Alerting](weeks/week7-siem-alerting.md) — Automated alerts, correlation rules, playbooks (coming soon)
- [Week 8: Capstone](weeks/week8-capstone.md) — Full attack chain detection, multi-stage correlation (coming soon)

## Key Learnings

### Technical Skills
- ✓ Splunk administration & SPL query development (aggregate functions, field extraction, rex patterns)
- ✓ Windows event forensics (Event IDs, Logon Types, Sub_Status codes)
- ✓ Group Policy configuration for security auditing
- ✓ Sysmon deployment & log enrichment (EventCode 1, 10, 22, etc.)
- ✓ Active Directory attack detection & Kerberoasting analysis
- ✓ Linux log analysis (auditd, auth.log, syslog, bash_history)
- ✓ Network traffic analysis (PFSense firewall logs, DNS queries, frequency analysis)
- ✓ Hypothesis-driven threat hunting & behavioral anomaly detection

### Critical Insights
- **Audit policies must be enabled *before* logs appear** — EventCode 4720 and 4698 require explicit GPO configuration
- **Field name accuracy matters in Splunk** — Typos in dashboard visualizations break results
- **Advanced Sysmon configuration is required for sensitive detections** — ProcessAccess (EventCode 10) for LSASS needs explicit rules
- **Correlation queries are powerful** — Multi-stage detections (account creation → privilege escalation) catch attacks others miss
- **Baseline-first threat hunting** — Establishing clean baselines before hunts prevents false positives and finds anomalies
- **Parent-child process chains reveal evasion** — Suspicious relationships catch attacks even when individual binaries are legitimate
- **PPL (Protected Process Light) is kernel-level protection** — Separate from Defender; requires explicit disabling for LSASS testing

## Progress Metrics

| Metric | Value |
|---|---|
| **Lab Hours Invested** | ~20 hours |
| **Detection Queries Built** | 16+ |
| **MITRE Techniques Detected** | 13 |
| **Dashboards Created** | 2 (AD Health Monitor, Threat Hunting Control Center) |
| **Confidence Level** | 6/10 — Strong grasp of detection engineering, behavioral hunting, and SIEM operations |

## For SOC Analyst Interviews

This lab demonstrates:

✅ **Log analysis at scale** — Can ingest, parse, aggregate, and correlate logs from multiple sources  
✅ **Detection engineering** — Build rules for known IOCs (Kerberoasting, brute force, etc.)  
✅ **Threat hunting** — Hypothesis-driven search for unknown attacks using behavioral anomalies  
✅ **SIEM proficiency** — Splunk administration, dashboard design, alert tuning, correlation rules  
✅ **MITRE ATT&CK framework** — Map real attacks to techniques and tactics  
✅ **Incident investigation flow** — Alert validation → baselining → simulation → analysis → documentation  
✅ **Linux & Windows forensics** — Understand OS-level logging and attack surfaces  
✅ **Network security** — Firewall analysis, DNS monitoring, C2 detection  

## Contact

**GitHub:** [netcur10s](https://github.com/netcur10s)  
**LinkedIn:** [linkedin.com/in/vic1101](https://linkedin.com/in/vic1101)  
**Email:** v.echevarria@proton.me