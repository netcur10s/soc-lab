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
| 1 | [Lab setup & Splunk fundamentals](docs/week1.md) | Beginner | ✓ Completed — May 13, 2026 |
| 2 | [Windows event log analysis](docs/week2.md) | Beginner | ✓ Completed — May 19, 2026 |
| 3 | [Active Directory attack detection](docs/week3.md) | Beginner-Intermediate | ✓ Completed — May 20, 2026 |
| 4 | Linux syslog & auditd | Intermediate | Not started |
| 5 | Network detection (PFSense, DNS) | Intermediate | Not started |
| 6 | Threat hunting with MITRE ATT&CK | Intermediate | Not started |
| 7 | SIEM alerting & correlation rules | Advanced | Not started |
| 8 | Capstone: full attack chain detection | Advanced | Not started |

## Session Log

| **Date** | **Duration** | **Week / Topic** | **What I did** | **Confidence** |
| --- | --- | --- | --- | --- |
| May 13, 2026 | ~6 hrs | Week 1 / Lab Setup | Full lab setup: Splunk forwarders on all 3 machines, Sysmon install and permissions fix, NTP hierarchy, audit policy, first ART detection, Bloodhound observation, dashboard created | 3/10 |
| May 16, 2026 | ~4 hrs | Week 2 / Windows Event Logs | Event ID cheat sheet, brute force simulation + Sub_Status analysis, backdoor account creation via net user, GPO audit policy setup from DC01, Restricted Groups GPO for jsmith, correlated 4720+4732 detection, Splunk real-time alert created | 4/10 |
| May 19, 2026 | ~4.5 hrs | Week 2-3 / AD Attack Detection | Fixed ART powershell-yaml, fixed Splunk forwarder permissions via Event Log Readers, full audit policy via GPO, verified WS01+WS02 log sources, detected 4720/4726/4625/4769/4624, created svc_sql, built AD Health Monitor dashboard | 4/10 |
| May 20, 2026 | ~2.5 hrs | Week 3 / Scheduled Tasks + LSASS | Fixed dashboard typos (no mvindex needed), enabled Audit Other Object Access Events via GPO, ran T1053.005-2 scheduled task attack, detected via 4698, added 5th dashboard panel, attempted T1003.001 LSASS dump (succeeded but no telemetry), learned Sysmon EventCode 10 requirements, marked Week 3 complete | 4/10 |
