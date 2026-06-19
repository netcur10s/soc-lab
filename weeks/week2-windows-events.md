# Week 2: Windows Event Log Analysis & Brute Force Detection

**Date:** May 16-19, 2026  
**Difficulty:** Beginner  
**Duration:** ~4.5 hours  

## What This Week Demonstrates
- Built threshold-based detection queries for brute force and account creation using Windows Event IDs
- Configured domain-wide audit policy via Group Policy to ensure consistent log coverage across all endpoints
- Created first automated Splunk alert that fires on suspicious account activity without manual searching
- Identified and resolved a Splunk forwarder permissions issue blocking Security event log collection

## Overview

Week 2 transitions from **infrastructure** to **threat detection**. We build core detection queries for Windows event IDs, simulate attacks using Atomic Red Team, and create our first automated Splunk alerts.

**Key Outcome:** Detect brute force attacks (EventCode 4625), account creation (EventCode 4720/4732), and configure alert rules that fire automatically.

## Core Windows Event IDs Reference

| EventCode | Event Name | Detection Use | Status |
|---|---|---|---|
| 4624 | Successful Logon | Baseline auth, spot unusual logon types/times | ✅ Built |
| 4625 | Failed Logon | Brute force detection (5+ failures in 60s) | ✅ Built |
| 4648 | Logon with Explicit Credentials | Pass-the-hash / lateral movement | Observed |
| 4672 | Special Privileges Assigned | Admin logon detection | Baseline |
| 4688 | Process Created | Process execution tracking (with Sysmon preferred) | Week 1 ✅ |
| 4720 | User Account Created | New account (attacker backdoor) | ✅ Built |
| 4732 | Member Added to Local Group | Privilege escalation to Administrators | ✅ Built |

**Sub_Status Codes (4625):**
- `0xC0000064` = Username not found (attacker enumerating users)
- `0xC000006A` = Wrong password (credential attack)

## Tasks Completed

### Task 1: Build Windows Event ID Cheat Sheet

Created comprehensive reference documenting all critical EventCodes with:
- What each event means
- Why it matters for detection
- Common false positives
- Related events to correlate with

**Documented 8 core Event IDs** with practical examples.

**Event ID Reference in Splunk:**

![EventCode 4625 with Sub_Status Breakdown](./screenshots/week2-01-eventcode-4625-substatus.png)
*Splunk search showing failed logon events (EventCode 4625) broken down by Sub_Status codes - 0xC0000064 (username not found) vs 0xC000006A (wrong password)*

### Task 2: Simulate Brute Force Attack with Atomic Red Team

**Objective:** Trigger EventCode 4625 (failed logons) and detect via threshold rule

**Attack Simulation:**
```powershell
# Run ART T1110.001 (Brute Force - Windows)
Invoke-AtomicTest T1110.001 -TestNumbers 1
```

**What Happened:**
- Simulated failed logon attempts against domain user account
- 10+ failures in 60-second window captured in EventCode 4625
- Sub_Status showed `0xC000006A` (wrong password — credential attack)

**Detection Query Built:**
```spl
index=windows EventCode=4625 
| eval user=mvindex(Account_Name,1) 
| bucket _time span=60s 
| stats count by _time, user, Source_Network_Address, host 
| where count >= 5 
| sort -count
```

**Logic:**
1. Filter for failed logons (EventCode 4625)
2. Extract username from multivalue Account_Name field
3. Bucket events into 60-second windows
4. Count failures per user per source per minute
5. Alert if 5+ failures in that window

**Result:** ✅ Brute force detected with high confidence (0 false positives expected)

**Detection Results:**

![Brute Force Detection - Failed Logon Count](./screenshots/week2-02-brute-force-count.png)
*Splunk search results showing 10+ failed login attempts from single source in 60-second window*

![Sub_Status Code Analysis](./screenshots/week2-03-substatus-credential-attack.png)
*Sub_Status breakdown showing 0xC000006A (wrong password attempts) indicating credential attack vs username enumeration*

### Task 3: Configure Group Policy for Audit Policy

**Objective:** Push audit policy domain-wide from DC01 to ensure all machines log critical events

**Steps on DC01:**
1. Opened Group Policy Management Console (GPMC)
2. Edited Default Domain Policy
3. Configured: Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies
4. Enabled:
   - **Account Management:** Create, Modify, Delete (Success + Failure)
   - **Logon/Logoff:** Logon, Logoff (Success + Failure)
   - **Account Logon:** Credential Validation, Kerberos TGT (Success + Failure)
5. Applied policy: `gpupdate /force` on all endpoints

**Result:** All domain-joined machines now log EventCode 4720 (account creation), 4625 (failed logons), 4769 (Kerberos)

**Configuration & Results:**

![Group Policy Audit Policy Configuration](./screenshots/week2-04-gpo-audit-policy.png)
*Group Policy Management Editor showing Advanced Audit Policy Configuration with Account Management and Logon/Logoff enabled for Success + Failure*

![EventCode 4720 Flowing to Splunk](./screenshots/week2-05-eventcode-4720-accounts.png)
*Splunk search: `index=windows EventCode=4720 | stats count by host` showing new user accounts logged on all domain machines*

### Task 4: Simulate Account Creation & Privilege Escalation

**Objective:** Detect attacker creating backdoor account and adding to Administrators group

**Attack Sequence:**
```powershell
# Simulate jsmith (attacker) creating backdoor account
Invoke-AtomicTest T1136.001 -TestNumbers 1

# This triggers:
# - EventCode 4720 (User account created)
# - EventCode 4732 (Member added to Administrators)
```

**Events Captured:**
- **EventCode 4720:** New user "jdoe" created by "jsmith"
- **EventCode 4732:** "jdoe" added to local Administrators group

**Challenge:** Account_Name field is multivalue (contains both creator and created account)
- `mvindex(Account_Name,0)` = actor (who created it)
- `mvindex(Account_Name,1)` = target (what was created)

**Detection Query (Correlated):**
```spl
index=windows (EventCode=4720 OR EventCode=4732) 
| eval Computer=coalesce(Computer, host) 
| eval EventType=case(EventCode=4720, "Account Created", EventCode=4732, "Added to Administrators") 
| table _time, Computer, EventCode, EventType, Account_Name, SAM_Account_Name 
| sort _time
```

**Result:** ✅ Detected account creation + privilege escalation in single correlated view

**Correlated Detection:**

![Account Creation & Privilege Escalation Sequence](./screenshots/week2-06-account-creation-4720.png)
*Splunk showing EventCode 4720 (jsmith creating new account jdoe) followed immediately by EventCode 4732 (jdoe added to Administrators group)*

![Multivalue Account_Name Field](./screenshots/week2-07-account-name-multivalue.png)
*Raw Splunk event showing Account_Name field containing both creator (jsmith) and target (jdoe); using mvindex() to separate them*

### Task 5: Create First Splunk Alert

**Objective:** Automatically fire alert when suspicious account activity detected

**Alert Configuration:**
- **Name:** Account Creation Suspicious Activity
- **Search:** EventCode 4720 OR EventCode 4732 (account creation or escalation)
- **Schedule:** Real-time
- **Condition:** Fire when results > 0 in 60-second window
- **Throttle:** Per Computer (avoid duplicate alerts)
- **Severity:** High

**Alert Action:** Log to `index=alerts` for later investigation

**Result:** Alert now fires automatically when backdoor account is created; analyst can investigate without manual searching.

**Alert Configuration & Execution:**

![Splunk Alert Manager - New Alert Created](./screenshots/week2-08-alert-manager-config.png)
*Splunk Alert Manager showing "Account Creation Suspicious Activity" alert with Real-time schedule, High severity, throttle per Computer*

![Alert Firing from ART Simulation](./screenshots/week2-09-alert-fired-notification.png)
*Alert notification triggered when Atomic Red Team T1136.001 simulates account creation and privilege escalation*

### Task 6: Fix Splunk Forwarder Permissions Issue

**Problem:** jsmith account (used for testing) couldn't read Security event log on WS01

**Root Cause:** jsmith had no permissions to access Windows Event Log

**Solution:**
```powershell
# On WS01, add jsmith to Event Log Readers group
Add-LocalGroupMember -Group "Event Log Readers" -Member "lab\jsmith"

# Verify
Get-LocalGroupMember -Group "Event Log Readers"

# On DC01, push via Group Policy for domain-wide
# New GPO: Restricted Groups → Event Log Readers → Add jsmith
# Result: All machines now allow jsmith to read Security logs
```

**Result:** Splunk forwarder (running as jsmith) can now read and forward Security events

**Permission Configuration:**

![Local Users and Groups - Event Log Readers](./screenshots/week2-10-event-log-readers-group.png)
*Local Users and Groups showing jsmith added to Event Log Readers group on WS01*

![Security Events Now Flowing in Splunk](./screenshots/week2-11-security-events-flowing.png)
*Splunk search confirming Security event logs now flowing after jsmith account added to Event Log Readers*

## Key Learnings

### Technical
- **EventCode 4625 Sub_Status reveals attack type:** `0xC0000064` (username enumeration) vs `0xC000006A` (password attack)
- **Multivalue fields require mvindex() extraction:** Account_Name contains both actor and target; must extract separately
- **Audit policy scope matters:** Enabling on single machine doesn't help; must push via GPO domain-wide
- **Correlation queries are more powerful than single-event detection:** EventCode 4720 + 4732 together = account backdoor

### Operational
- **Thresholds prevent alert fatigue:** 5+ failures in 60s prevents single-failure noise
- **Throttling by Computer prevents duplicate alerts:** One alert per machine, not per event
- **Splunk alerts integrate into SOC workflow:** Analysts get notified automatically; no need for manual searching

## Splunk Query Library

| Detection | Query | Confidence |
|---|---|---|
| Brute Force (5+ failures in 60s) | `index=windows EventCode=4625 \| eval user=mvindex(Account_Name,1) \| bucket _time span=60s \| stats count by _time, user, Source_Network_Address \| where count >= 5` | High |
| Account Creation (clean) | `index=windows EventCode=4720 \| eval Who_Created=mvindex(Account_Name,0) \| eval Account_Created=mvindex(Account_Name,1) \| table _time, host, Who_Created, Account_Created` | High |
| Account Escalation Correlated | `index=windows (EventCode=4720 OR EventCode=4732) \| table _time, Computer, EventCode, Account_Name, SAM_Account_Name \| sort _time` | Very High |

## Troubleshooting Reference

| Issue | Cause | Fix |
|---|---|---|
| EventCode 4625 not appearing | Logon/Logoff audit not enabled | Enable via GPO → Audit Logon/Logoff (Success + Failure), run gpupdate /force |
| EventCode 4720 not appearing | Account Management audit not enabled | Enable via GPO → Audit Account Management, run gpupdate /force |
| Account_Name shows blank | SID not resolved quickly | Pair with SAM_Account_Name field; use mvindex for manual extraction |
| Splunk forwarder can't read Security log | Account lacks permissions | Add account to Event Log Readers group; can use GPO for domain-wide application |

## Next Steps (Week 3)

Week 3 builds **Active Directory attack detection:**
- Create service account vulnerable to Kerberoasting
- Detect EventCode 4769 (Kerberos ticket requests)
- Detect lateral movement (EventCode 4624 Logon_Type=3)
- Build 5-panel AD Health Monitor dashboard

**Detection pipeline now mature; ready for advanced AD attacks.**

**Week 2 Status:** ✅ COMPLETE  

## Navigation

← [Back to Main SOC Lab Overview](../Readme.md)  
[Week 3: Active Directory Detection →](./week3-active-directory.md)