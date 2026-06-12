# Week 1: Lab Setup & Splunk Fundamentals

**Date:** May 13, 2026  
**Difficulty:** Beginner  
**Duration:** ~6 hours  
**Confidence After:** 3/10 — Can complete tasks with guidance; improving with repetition

## Overview

Week 1 focuses on building the **foundational infrastructure** for the entire lab. The goal is to get logs flowing from all endpoints into Splunk, ensure correct event routing, deploy Sysmon for process-level telemetry, and solve the inevitable timestamp synchronization issues that plague distributed labs.

**Key Outcome:** All endpoints (WS01, WS02, DC01) are forwarding logs to Splunk in the correct index (windows), Sysmon is capturing process creation events (EventCode 1), and the time hierarchy is synchronized via NTP.

## Tasks Completed

### Task 1: Install Splunk Universal Forwarder on All Endpoints

**Objective:** Configure log forwarding from Windows endpoints to Splunk

**Steps:**
1. Downloaded Splunk Universal Forwarder from splunk.com
2. Installed on WS01, WS02, DC01 with deployment server pointing to Splunk indexer (10.10.20.3)
3. Configured `inputs.conf` to forward:
   - Windows Security Event Log → index=windows
   - Sysmon logs → index=windows
   - Active Directory event logs → index=windows

**Key Issue Encountered:**
- **Problem:** Events were landing in `index=main` instead of `index=windows`
- **Root Cause:** Conflicting `inputs.conf` files; forwarder was using default routing
- **Solution:** Removed conflicting inputs.conf, re-deployed configuration, verified via `index=windows` search

**Verification in Splunk:**

![Splunk Forwarders Connected](./screenshots/week1-01-forwarder-settings.png)
*Splunk Settings → Data Inputs → Forwarding and Receiving showing WS01, WS02, DC01 connected*

Query all events flowing into windows index:

![Windows Index Events by Host](./screenshots/week1-02-windows-index-count.png)
*Splunk search: `index=windows | stats count by host` showing all 3 hosts forwarding successfully*


### Task 2: Install and Configure Sysmon

**Objective:** Deploy Sysmon on WS01, WS02, DC01 for process-level telemetry

**Steps:**
1. Downloaded Sysmon from sysinternals.com
2. Created `sysmonconfig-export.xml` with rules for:
   - EventCode 1 (Process Creation) — log all processes including ParentImage, CommandLine, User
   - EventCode 22 (DNS Query) — for network-level detection
   - EventCode 3 (Network Connection) — for C2 and lateral movement
3. Installed via: `Sysmon64.exe -i sysmonconfig-export.xml`
4. Configured Splunk Universal Forwarder to forward Sysmon logs

**Key Issue Encountered:**
- **Problem:** EventCode 5 access denied — forwarder couldn't read Sysmon logs
- **Root Cause:** Universal Forwarder was running as Local Service (no permissions)
- **Solution:** Changed service account: `sc config SplunkForwarder obj= LocalSystem` and restarted
- **Result:** Logs now flowing, EventCode 1 events visible in Splunk

**Commands:**
```powershell
# Install Sysmon
Sysmon64.exe -i sysmonconfig-export.xml

# Verify installation
Get-Service | Select-Object Name, Status | findstr /I sysmon

# Check event logs
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Select-Object Id | Group-Object Id | Sort-Object Count -Descending
```

**Verification:**

![Sysmon Events in Event Viewer](./screenshots/week1-03-event-viewer-sysmon.png)
*Windows Event Viewer → Applications and Services Logs → Microsoft-Windows-Sysmon/Operational showing EventCode 1 entries*

![Sysmon Process Creation in Splunk](./screenshots/week1-04-splunk-sysmon-eventcode1.png)
*Splunk search: `index=windows EventCode=1 | head 20` showing process creation with ParentImage, Image, CommandLine, User*


### Task 3: Configure Network Time Protocol (NTP) Hierarchy

**Objective:** Synchronize time across all lab machines to prevent clock skew and log delays

**Problem:** All machines reporting different times; logs were appearing out of order in Splunk with 5–10 minute delays

**Solution: Establish NTP Hierarchy**

| Tier | Host | Role | Upstream | Notes |
|---|---|---|---|---|
| 0 | PFSense | External Time Source | pool.ntp.org | Gateway; syncs to internet NTP |
| 1 | DC01 | Primary NTP Server | PFSense | Domain Controller acts as domain time server |
| 2 | WS01, WS02 | NTP Clients | DC01 | Workstations sync to DC via domain |
| 2 | Splunk | NTP Client | PFSense | SIEM syncs to gateway |

**Steps on DC01 (Windows Server 2022):**
```powershell
# Set DC01 to sync with PFSense as NTP source
reg add "HKLM\SYSTEM\CurrentControlSet\Services\w32time\Parameters" /v NtpServer /d "10.10.20.254,0x9" /f

# Force time sync
net stop w32time
net start w32time
w32tm /resync /force

# Verify sync
w32tm /query /status
```

**Steps on WS01, WS02 (Windows 10/11):**
```powershell
# Set to sync with DC01
w32tm /config /manualpeerlist:"10.10.10.3" /syncfromflags:manual /reliable:yes /update
net stop w32time
net start w32time
w32tm /resync /force
```

**Verification:**

![NTP Status on WS01](./screenshots/week1-05-w32tm-query-status.png)
*PowerShell: `w32tm /query /status` showing Leap Indicator, Stratum, Reference Clock, Precision*

![Splunk Timeline with Correct Order](./screenshots/week1-06-splunk-timeline-correct.png)
*Splunk dashboard showing events in correct chronological order (no backwards time jumps)*

**Result:** All machines now within 1 second of each other; Splunk events appear in correct chronological order.


### Task 4: Enable Audit Policy for Process Creation

**Objective:** Ensure Windows logs process creation events (EventCode 4688) for detection analysis

**Steps:**
1. Opened `gpedit.msc` on DC01
2. Navigated to: Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → Detailed Tracking → Audit Process Creation
3. Set to: **Success and Failure**
4. Applied group policy with: `gpupdate /force`
5. Verified logs appearing on WS01, WS02

**Configuration:**

![Group Policy Editor - Audit Process Creation](./screenshots/week1-07-gpedit-audit-policy.png)
*Group Policy Management Editor showing "Audit Process Creation" configured for Success and Failure*

**Result in Splunk:**

![EventCode 4688 in Splunk](./screenshots/week1-08-splunk-eventcode4688.png)
*Splunk search: `index=windows EventCode=4688 | stats count by host` showing process audit on all domain machines*


### Task 5: Run First Detection Simulation (Atomic Red Team)

**Objective:** Test the entire pipeline by running ART T1059.001 (PowerShell execution) and confirming detection in Splunk

**Steps:**
1. Installed Atomic Red Team on WS01: `Invoke-AtomicRedTeam -getAtomics`
2. Ran T1059.001 Test 1: `Invoke-AtomicTest T1059.001 -TestNumbers 1`
3. Verified Sysmon EventCode 1 captured the execution:
   - Image: `C:\Windows\System32\powershell.exe`
   - CommandLine: `powershell.exe -NoProfile -Command "Write-Host 'Hello from Atomic Red Team'"`
   - ParentImage: `C:\Windows\explorer.exe`

**Attack Simulation:**

![Atomic Red Team PowerShell Execution](./screenshots/week1-09-art-powershell-command.png)
*PowerShell: `Invoke-AtomicTest T1059.001 -TestNumbers 1` running on WS01*

**Detection Result:**

![PowerShell Execution Detected in Splunk](./screenshots/week1-10-splunk-powershell-detection.png)
*Splunk showing Sysmon EventCode 1: powershell.exe spawned by explorer.exe with full CommandLine visibility*

**Result:** ✅ Full detection pipeline working end-to-end: Attack → Sysmon captures → Forwarder sends → Splunk indexes → Searchable

### Task 6: Observe Active Directory Enumeration (Bloodhound/SharpHound)

**Objective:** Note that AD enumeration tools generate high volumes of network logons; establish baseline for Week 3 detection

**Observation:**
- Ran SharpHound AD enumeration tool from attacking machine
- DC01 received 10,000+ EventCode 4624 (successful logons) from same source in 5 minutes
- Result: EventCode 4624 Logon_Type=3 (network) flood from enumeration

**Baseline Observation:**

![Bloodhound Enumeration Baseline](./screenshots/week1-11-splunk-bloodhound-spike.png)
*Splunk: `index=windows EventCode=4624 Logon_Type=3 | stats count by Workstation_Name` showing massive enumeration activity from single source*

**Significance:** This is a **false positive baseline** that we'll filter out in Week 3 when building AD detection rules.


## Architecture Diagram

```
┌─────────────────────────────────────────────────┐
│                   PFSense Gateway                │
│                 192.168.40.13/24                 │
│            (NTP Source, Internet Access)         │
└──────────────┬──────────────────────────────────┘
               │
        ┌──────┼──────┐
        │      │      │
    ┌───▼──┐  │   ┌──▼────┐
    │WS01  │  │   │DC01    │ (NTP Server tier 1)
    │10.10 │  │   │10.10   │
    │.10.1 │  │   │.10.3   │
    └──────┘  │   └────┬───┘
              │        │
           ┌──┴────────┼────┐
           │           │    │
        ┌──▼──┐    ┌───▼────┐
        │WS02 │    │Splunk   │
        │10.10│    │10.10.20.3
        │.10.2│    │
        └─────┘    └────────┘
```


## Key Learnings

### Technical
- **Forwarder routing matters:** Conflicting `inputs.conf` files cause events to land in wrong indexes
- **Service account permissions:** Splunk Forwarder running as LocalService can't read Sysmon logs; must run as LocalSystem
- **NTP hierarchy prevents chaos:** Clock skew causes logs to appear out of order and delayed in SIEM
- **Sysmon configurations require understanding:** EventCode 1 is powerful for execution detection; need to understand which fields are critical
- **Audit policies must be pushed domain-wide:** Enabling on individual machines doesn't scale; must use Group Policy

### Operational
- **Baseline before you hunt:** Understanding "normal" traffic (like Bloodhound enumeration) prevents false positives
- **Full pipeline testing is critical:** Running ART confirmed that logs actually flow from endpoint → forwarder → SIEM
- **Documentation from day 1:** Recording issues (forwarder permissions, NTP skew) helps troubleshoot later


## Troubleshooting Reference

| Issue | Cause | Fix |
|---|---|---|
| Events landing in index=main | Conflicting inputs.conf routing | Remove/rename conflicting inputs.conf, restart forwarder |
| EventCode 5 access denied | Forwarder running as Local Service | `sc config SplunkForwarder obj= LocalSystem` + restart |
| Log delays in Splunk (5-10min) | Clock skew across machines | Establish NTP hierarchy via group policy, sync to DC |
| No Sysmon events | Sysmon not installed or misconfigured | Run `Sysmon64.exe -c sysmonconfig-export.xml` to update config |
| EventCode 4688 not appearing | Process audit not enabled | Enable "Audit Process Creation" via GPO on DC, run gpupdate /force |


## Next Steps (Week 2)

Week 2 builds on this foundation to detect actual attacks:
- Simulate brute force attacks and detect via EventCode 4625
- Simulate account creation and detect via EventCode 4720/4732
- Build Splunk alerts that fire automatically
- Create first dashboard

**Infrastructure is now ready for detection engineering.**


**Week 1 Status:** ✅ COMPLETE  
**Confidence:** 3/10 (foundation is solid, will improve with repetition)

---

## Navigation

← [Back to Main SOC Lab Overview](../README.md)  
[Week 2: Windows Event Log Analysis →](../Week2-Windows-Events/README.md)