# Curriculum & Progress Tracker

## Current Status

| **Field** | **Your Answer** |
| --- | --- |
| Current week | Week 4 |
| Current topic | Linux syslog & auditd |
| Last session date | May 20, 2026 |
| Next session goal | Start Week 4 — Install Splunk forwarder on Metasploitable 2, configure syslog forwarding |
| Overall confidence (1-10) | 5 — Week 3 complete. AD attack detection solid, dashboard operational, comfortable with audit policy + SPL |

## 8-Week Curriculum Overview

| **Week** | **Topic** | **Difficulty** | **Status** |
| --- | --- | --- | --- |
| 1 | Lab setup & Splunk fundamentals | Beginner | ✓ Completed — May 13, 2026 |
| 2 | Windows event log analysis | Beginner | ✓ Completed — May 19, 2026 |
| 3 | Active Directory attack detection | Beginner-Intermediate | ✓ Completed — May 20, 2026 |
| 4 | Linux syslog & auditd | Intermediate | Not started |
| 5 | Network detection (PFSense, DNS) | Intermediate | Not started |
| 6 | Threat hunting with MITRE ATT&CK | Intermediate | Not started |
| 7 | SIEM alerting & correlation rules | Advanced | Not started |
| 8 | Capstone: full attack chain detection | Advanced | Not started |

## Week 1 Detail — Completed ✓

| **Field** | **Detail** |
| --- | --- |
| Difficulty | Beginner |
| Status | ✓ Completed |
| Date started | May 13, 2026 |
| Date completed | May 13, 2026 |
| Confidence after | 3/10 — Can complete tasks with guidance. Improving with repetition. |

**Tasks completed:**

✓  Installed Splunk Universal Forwarder on WS01, WS02, DC-01

✓  Resolved index routing issue (events landing in main vs windows index)

✓  Installed and configured Sysmon on all three endpoints

✓  Fixed Sysmon errorCode=5 permission issue by running forwarder as LocalSystem

✓  Configured NTP hierarchy: PFSense → DC-01 → WS01/WS02

✓  Resolved clock skew causing log delays in Splunk

✓  Enabled audit process creation on WS01, WS02, DC-01

✓  Ran ART T1059.001 and detected it in Splunk via Sysmon EventCode=1

✓  Observed Bloodhound/SharpHound AD enumeration telemetry on DC-01

✓  Created first Splunk dashboard — WS01 Logon Activity

## Week 2 Detail — Completed ✓

| **Field** | **Detail** |
| --- | --- |
| Difficulty | Beginner |
| Status | ✓ Completed |
| Date started | May 16, 2026 |
| Date completed | May 19, 2026 |
| Confidence after | 4/10 — GPO, audit policy, SPL detection queries, Splunk alerting, and AD attack detection completed. |

**Tasks completed:**

✓  Built Windows Event ID cheat sheet — all 8 core IDs documented with notes

✓  Simulated brute force with ART T1110.001 — detected via EventCode=4625

✓  Analysed Sub_Status codes: 0xC0000064 (username enumeration) vs 0xC000006A (credential attack)

✓  Pushed domain-wide audit policy via GPO from DC01

✓  Configured Restricted Groups GPO — jsmith and jdoe added to local Administrators on WS01

✓  Simulated backdoor account creation via net user commands as jsmith

✓  Detected 4720 (account created) and 4732 (added to Administrators) in Splunk

✓  Built correlated 4720+4732 detection query using coalesce and eval

✓  Created real-time Splunk alert — High severity, throttled 60s by Computer

✓  Fixed Splunk forwarder permissions — jsmith added to Event Log Readers via DC01

✓  Configured full audit policy on DC01 — Kerberos, Credential Validation, DS Access, Account Management

## Week 3 Detail — Completed ✓

| **Field** | **Detail** |
| --- | --- |
| Difficulty | Beginner-Intermediate |
| Status | ✓ Completed |
| Date started | May 19, 2026 |
| Date completed | May 20, 2026 |
| Confidence after | 5/10 — AD attack detection complete. Built 5-panel dashboard, detected Kerberoasting, lateral movement, scheduled task persistence. Learned LSASS detection requirements for future. |

**Tasks completed:**

✓  Created svc_sql Kerberoastable service account on DC01 (SPN: MSSQLSvc/DC-01.lab.local:1433, RC4 forced)

✓  Ran ART T1558.003 — detected Kerberoasting via EventCode=4769 + Ticket_Encryption_Type=0x17

✓  Ran ART T1021.002 — detected lateral movement via EventCode=4624 Logon_Type=3

✓  Built AD Health Monitor dashboard in Splunk (5 panels total)

✓  Fixed dashboard field typos (Account_Name, Service_Name, Who_Created)

✓  Enabled "Audit Other Object Access Events" via GPO for EventCode 4698

✓  Ran ART T1053.005-2 — detected scheduled task creation via EventCode 4698 (task name: "spawn")

✓  Added 5th panel to dashboard: Scheduled Tasks Created

✓  Attempted T1003.001 LSASS dump — test succeeded (comsvcs.dll method) but no Sysmon telemetry captured

✓  Documented LSASS detection theory — requires Sysmon EventCode 10 with advanced config (revisit in Week 6)

**Key learnings:**
- Audit policy must be enabled via GPO or using auditpol command before events appear in logs
- Dashboard field names must match exactly (typos break visualizations)
- Some detections (like LSASS access) require advanced Sysmon configuration
- Correlation queries (4720+4732, 4698) are powerful for catching attack chains

**Deferred to Week 6:**
- T1048.003 DNS exfiltration (advanced Sysmon EventCode 22 analysis)
- Advanced Sysmon EventCode 10 configuration for LSASS detection
- Multi-stage correlation alerting

## Session Log

| **Date** | **Duration** | **Week / Topic** | **What I did** | **Confidence** |
| --- | --- | --- | --- | --- |
| May 13, 2026 | ~6 hrs | Week 1 / Lab Setup | Full lab setup: Splunk forwarders on all 3 machines, Sysmon install and permissions fix, NTP hierarchy, audit policy, first ART detection, Bloodhound observation, dashboard created | 3/10 |
| May 16, 2026 | ~4 hrs | Week 2 / Windows Event Logs | Event ID cheat sheet, brute force simulation + Sub_Status analysis, backdoor account creation via net user, GPO audit policy setup from DC01, Restricted Groups GPO for jsmith, correlated 4720+4732 detection, Splunk real-time alert created | 4/10 |
| May 19, 2026 | ~4.5 hrs | Week 2-3 / AD Attack Detection | Fixed ART powershell-yaml, fixed Splunk forwarder permissions via Event Log Readers, full audit policy via GPO, verified WS01+WS02 log sources, detected 4720/4726/4625/4769/4624, created svc_sql, built AD Health Monitor dashboard | 4/10 |
| May 20, 2026 | ~2.5 hrs | Week 3 / Scheduled Tasks + LSASS | Fixed dashboard typos (no mvindex needed), enabled Audit Other Object Access Events via GPO, ran T1053.005-2 scheduled task attack, detected via 4698, added 5th dashboard panel, attempted T1003.001 LSASS dump (succeeded but no telemetry), learned Sysmon EventCode 10 requirements, marked Week 3 complete | 4/10 |
