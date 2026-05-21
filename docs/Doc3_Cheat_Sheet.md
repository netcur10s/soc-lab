# Personal Cheat Sheet & Growing Reference

## 1. Windows Event ID Cheat Sheet

| **Event ID** | **Event Name** | **Why it matters** | **My Notes** | **Known?** |
| --- | --- | --- | --- | --- |
| 4624 | Successful logon | Baseline — look for unusual logon types (type 3=network, type 10=remote interactive) | Successful logon — correlate logon type with event to spot possible attacks | ✓ |
| 4625 | Failed logon | Brute force detection — alert on 5+ failures in 60s. Sub_Status: 0xC0000064=username not found, 0xC000006A=wrong password | Possible signs of brute force. Sub_Status tells you if attacker is enumerating usernames or guessing passwords | ✓ |
| 4648 | Logon with explicit credentials | Pass-the-hash / lateral movement indicator | Usually not a human login — from a script or application. Possible signs of pass-the-hash or lateral movement | ✓ |
| 4672 | Special privileges assigned to new logon | Admin logon — who is getting elevated access? | Admin logon shows who logged in with elevated privileges. Pair with 4624 to confirm admin activity | ✓ |
| 4688 | Process created | Requires Sysmon or audit policy — catch malicious child processes | New process creation — look for malicious child processes used for priv escalation or lateral movement | ✓ |
| 4698 | Scheduled task created | Persistence mechanism — attackers love scheduled tasks | Detects persistence via scheduled tasks. Requires "Audit Other Object Access Events" enabled via GPO | ✓ |
| 4720 | User account created | New local account — could be attacker creating backdoor | Possible backdoor account creation. By itself could be normal — pair with 4732 to confirm escalation | ✓ |
| 4726 | User account deleted | Account deletion — attacker cleaning up | Pair with 4720 to see full account lifecycle. Rapid create+delete is a red flag | ✓ |
| 4732 | Member added to local group | Adding user to Administrators group | Privilege escalation indicator. Note: Member_Name may be blank (SID not resolved) — use 4720 SAM_Account_Name instead | ✓ |
| 4768 | Kerberos TGT requested | Authentication — look for unusual accounts or times | Kerberos Ticket Granting Ticket request — baseline normal domain auth | ✓ |
| 4769 | Kerberos service ticket requested | Kerberoasting — watch for RC4 encryption (0x17) | Ticket_Encryption_Type=0x17 = RC4 = Kerberoasting. AES (0x12) is normal | ✓ |
| 4771 | Kerberos pre-auth failed | Failed Kerberos auth — brute force against AD | Failed Kerberos authentication — possible password spray against domain | [ ] |
| 4776 | NTLM authentication attempt | Pass-the-hash when combined with lateral movement | NTLM auth — watch for unusual source machines or accounts | [ ] |
| 7045 | New service installed | Persistence / privilege escalation technique | Service installation — alternate persistence mechanism alongside scheduled tasks | ✓ |

## 2. Logon Type Reference

| **Type** | **Name** | **How auth happened** | **Primary threat signal** |
| --- | --- | --- | --- |
| 2 | Interactive | Physical keyboard at console | Unusual on servers, odd hours |
| 3 | Network | Over the network (SMB, shares) | Lateral movement — workstation to workstation |
| 5 | Service | Service account auth at startup | New/unknown service account + EventID 7045 |
| 7 | Unlock | Lock screen unlocked | Mostly noise — flag failures at odd hours |
| 10 | Remote Interactive | RDP session | High value — always check source IP |

## 3. Sysmon Event ID Reference

| **EventCode** | **What it captures** | **When to use it** |
| --- | --- | --- |
| 1 | Process created | Primary hunting event — any execution. Full CommandLine, ParentImage, hashes |
| 3 | Network connection | What did a process connect to after running |
| 7 | Image loaded (DLL) | Advanced — catch DLL injection later |
| 10 | Process Access | Detects when processes open handles to other processes (e.g., LSASS access). Requires advanced Sysmon config — very noisy by default |
| 11 | File created | Did the process drop a file on disk |
| 12/13 | Registry modified | Persistence mechanisms |
| 22 | DNS query | What domains did a process look up — C2 beaconing detection |

## 4. SPL Query Library

### 4.1 Foundational Queries

| **What it finds** | **SPL Query** |
| --- | --- |
| All events, first look | `index=* │ head 50` |
| All hosts logging to Splunk | `index=windows │ stats count by host │ sort -count` |
| Verify forwarder connections | `index=_internal source=*metrics.log group=tcpin_connections │ stats latest(_time) as last_seen by hostname` |
| All logons by host and type | `index=windows EventCode=4624 │ stats count by host, Account_Name, Logon_Type │ sort -count` |
| Failed logons | `index=windows EventCode=4625 │ stats count by host, Account_Name, Source_Network_Address │ sort -count` |
| Processes created (Sysmon) | `index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 │ table _time, host, Image, ParentImage, CommandLine` |
| New scheduled tasks | `index=windows EventCode=4698 │ table _time, host, Account_Name, Task_Name` |
| New local accounts (clean) | `index=windows EventCode=4720 │ eval Who_Created=mvindex(Account_Name,0) │ eval Account_Created=mvindex(Account_Name,1) │ table _time, host, Who_Created, Account_Created` |
| Events from last 2 minutes | `index=windows │ where _time >= relative_time(now(),"-2m") │ stats count by host, EventCode │ sort host` |

### 4.2 Detection Queries

| **Technique detected** | **SPL Query** |
| --- | --- | --- |
| Brute force (5+ failures in 60s) | `index=windows EventCode=4625 │ eval user=mvindex(Account_Name,1) │ bucket _time span=60s │ stats count by _time, user, Source_Network_Address, host │ where count >= 5 │ sort -count` |
| Brute force Sub_Status analysis | `index=windows EventCode=4625 │ eval user=mvindex(Account_Name,1) │ table _time, user, Source_Network_Address, Sub_Status │ sort -_time` |
| Account creation (clean fields) | `index=windows EventCode=4720 │ eval Who_Created=mvindex(Account_Name,0) │ eval Account_Created=mvindex(Account_Name,1) │ table _time, host, Who_Created, Account_Created` |
| Account deletion | `index=windows EventCode=4726 │ eval Who_Deleted=mvindex(Account_Name,0) │ eval Account_Deleted=mvindex(Account_Name,1) │ table _time, host, Who_Deleted, Account_Deleted` |
| Backdoor account + priv esc (correlated) | `index=windows (EventCode=4720 OR EventCode=4732) │ eval Computer=coalesce(Computer, host) │ eval EventType=case(EventCode=4720, "Account Created", EventCode=4732, "Added to Administrators") │ table _time, Computer, EventCode, EventType, Account_Name, SAM_Account_Name │ sort _time` |
| Kerberoasting (RC4 tickets) | `index=windows EventCode=4769 Ticket_Encryption_Type=0x17 │ table _time, host, Account_Name, Service_Name, Ticket_Encryption_Type │ sort -_time` |
| Lateral movement (network logons) | `index=windows EventCode=4624 Logon_Type=3 │ eval user=mvindex(Account_Name,1) │ table _time, host, user, Logon_Type, Source_Network_Address │ sort -_time` |
| Scheduled task persistence | `index=windows EventCode=4698 │ table _time, host, Account_Name, Task_Name │ sort -_time` |
| PowerShell execution | `index=windows EventCode=4688 (New_Process_Name=*powershell* OR New_Process_Name=*cmd*) │ table _time, host, Creator_Process_Name, New_Process_Name, Process_Command_Line` |
| PowerShell evasion flags | `index=windows EventCode=1 Image=*powershell* │ search CommandLine=*-enc* OR CommandLine=*-nop* OR CommandLine=*bypass* OR CommandLine=*IEX* │ table _time, host, ParentImage, CommandLine` |
| AD enumeration (Bloodhound) | `index=windows host=DC-01 EventCode=4624 Logon_Type=3 │ where _time >= relative_time(now(),"-10m") │ stats count by Account_Name, Workstation_Name │ sort -count │ where count > 10` |
| Lateral movement indicator | `index=windows EventCode=4624 │ stats dc(host) as machines_accessed, values(host) as hosts by Account_Name │ where machines_accessed > 1 │ sort -machines_accessed` |

## 5. Atomic Red Team Quick Reference

| **What it simulates** | **ART Command (run on WS01 in PowerShell as Admin)** | **MITRE ID** |
| --- | --- | --- |
| Run a single technique | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | T1059.001 |
| List all tests for a technique | `Invoke-AtomicTest T1059.001 -ShowDetailsBrief` | — |
| Install prerequisites | `Invoke-AtomicTest T1059.001 -GetPrereqs` | — |
| Cleanup after test | `Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup` | — |
| Create local account | `Invoke-AtomicTest T1136.001` | T1136.001 |
| Scheduled task persistence | `Invoke-AtomicTest T1053.005` | T1053.005 |
| Kerberoasting | `Invoke-AtomicTest T1558.003 -TestNumbers 5 -PromptForInputArgs` | T1558.003 |
| Credential dumping (LSASS) | `Invoke-AtomicTest T1003.001` | T1003.001 |
| SMB lateral movement | `Invoke-AtomicTest T1021.002` | T1021.002 |

## 6. MITRE ATT&CK Techniques Studied

| **ID** | **Name** | **Tactic** | **Ran in lab?** | **Can detect?** | **Quality** | **Notes** |
| --- | --- | --- | --- | --- | --- | --- |
| T1059.001 | PowerShell | Execution | ✓ | ✓ | 3/5 | |
| T1059.001 | Bloodhound/SharpHound AD enum | Discovery | ✓ (observed) | ✓ | 3/5 | |
| T1110.001 | Brute Force | Credential Access | ✓ | ✓ | 4/5 | |
| T1136.001 | Create Local Account | Persistence | ✓ | ✓ | 4/5 | |
| T1558.003 | Kerberoasting | Credential Access | ✓ | ✓ | 4/5 | |
| T1021.002 | SMB Lateral Movement | Lateral Movement | ✓ | ✓ | 3/5 | |
| T1053.005 | Scheduled Task | Persistence | ✓ | ✓ | 4/5 | Detected via EventCode 4698. Test created task named "spawn" successfully |
| T1003.001 | LSASS Memory Dump | Credential Access | ✓ | [ ] | — | Ran T1003.001-2 (comsvcs.dll method) successfully but no telemetry. Requires Sysmon EventCode 10 + advanced config. Revisit in Week 6 |
| T1048.003 | DNS Exfiltration | Exfiltration | [ ] | [ ] | | |

## 7. Lab IP Quick Reference

| **Host** | **IP** | **How to access** |
| --- | --- | --- |
| Splunk Web UI | 10.10.20.3 | http://10.10.20.3:8000 |
| Nessus Web UI | 10.10.20.6 | https://10.10.20.6:8834 |
| Wazuh Web UI | 10.10.20.5 | https://10.10.20.5 |
| WS01 (ART machine) | 10.10.10.1 | RDP or Proxmox console |
| WS02 | 10.10.10.2 | RDP or Proxmox console |
| DC-01 | 10.10.10.3 | RDP or Proxmox console |
| Kali Linux | 10.10.40.1 | Proxmox console or SSH |
| Parrot OS | 10.10.40.2 | Proxmox console or SSH |
| Metasploitable 2 | 10.10.30.1 | SSH (msfadmin/msfadmin) |
| DVWA | 10.10.30.2 | http://10.10.30.2 (admin/password) |
| WebGoat | 10.10.30.3 | http://10.10.30.3:8080/WebGoat |

## 8. Troubleshooting Notes

| **Issue** | **Fix** |
| --- | --- |
| Index routing — events landing in main not windows | Root cause: competing inputs.conf. Fix: rename conflicting file to .bak or apply server-side transforms.conf routing |
| Sysmon errorCode=5 access denied | Fix: `sc config SplunkForwarder obj= LocalSystem` in cmd.exe as Administrator, then restart forwarder service |
| Log delays in Splunk | Root cause: clock skew. Fix: sync all machines to PFSense via w32tm. Add checkpointInterval=5 to inputs.conf |
| NTPsec not syncing | Root cause: tos minclock 4 requires 4 NTP sources. Fix: change to tos minclock 1 minsane 1 in /etc/ntpsec/ntp.conf |
| ART T1136.001 returns 0 applicable tests | Fix: reinstall technique library — Install-AtomicRedTeam -getAtomics -Force. If no internet, use manual net user commands |
| 4720 not appearing in Splunk | Root cause: User Account Management auditing not enabled. Fix: push via GPO from DC01 |
| 4698 not appearing in Splunk | Root cause: "Audit Other Object Access Events" not enabled. Fix: Enable via GPO → Advanced Audit Policy Configuration → Object Access → Audit Other Object Access Events (Success + Failure) |
| 4732 Member_Name blank | Root cause: SID not resolved when account created and escalated rapidly. Fix: correlate with 4720 — use SAM_Account_Name |
| powershell-yaml module missing for ART | Fix: Save-Module on host machine, copy folder to C:\Program Files\WindowsPowerShell\Modules\powershell-yaml on WS01 |
| Splunk 4625 events not appearing (offline machines) | Root cause: jsmith lacks permission to read Security log. Fix: add jsmith to Event Log Readers group on DC01 via ADUC or PowerShell, then gpupdate /force on WS01 |
| Kerberoasting 4769 not appearing | Root cause: No user service accounts with SPNs in domain. Fix: create svc_sql with SPN MSSQLSvc/DC-01.lab.local:1433 and set msDS-SupportedEncryptionTypes=4 (RC4) |
| Account_Name field shows two values stacked | Root cause: multivalue field — Splunk maps both subject and target to same field name. Fix: use mvindex(Account_Name,0) for actor and mvindex(Account_Name,1) for target |
| T1003.001 no telemetry in Splunk | Root cause: Sysmon EventCode 10 (Process Access) not configured or too restrictive. LSASS access detection requires explicit Sysmon config for TargetImage=lsass.exe. Default configs exclude it due to noise. Revisit when tuning Sysmon |

## 9. Key Concepts Glossary

| **Term** | **My definition** |
| --- | | --- |
| SIEM | Security Information and Event Management — centralizes logs from across the environment for search, alerting, and correlation |
| IOC | Indicator of Compromise — specific artifact that signals a breach (IP, hash, domain, registry key) |
| TTP | Tactics, Techniques, Procedures — how attackers operate at a behavioral level, mapped to MITRE ATT&CK |
| Lateral movement | Attacker moving from one machine to another inside the network after initial compromise |
| Privilege escalation | Attacker gaining higher-level permissions than they currently have — e.g. from standard user to local admin or domain admin |
| SPL | Splunk Processing Language — pipeline-based query language for searching and transforming log data |
| Kerberoasting | Requesting Kerberos service tickets for service accounts then cracking them offline to get plaintext passwords. Detected via 4769 + Ticket_Encryption_Type=0x17 |
| Pass-the-hash | Using a stolen NTLM hash to authenticate without knowing the plaintext password |
| C2 | Command and Control — attacker infrastructure that communicates with malware on compromised machines |
| Threat hunting | Proactive search for attackers already in the environment using hypothesis-driven queries before alerts fire |
| Bloodhound | AD enumeration tool that maps attack paths to Domain Admin by querying LDAP — generates mass Type 3 logons on DC |
| GPO | Group Policy Object — configuration pushed from DC01 to domain-joined machines. Used to enforce audit policy, local group membership, and other settings domain-wide |
| Audit policy | Windows setting that controls which events get written to the Security event log. Must be enabled before events like 4720 will appear in Splunk |
| SPN | Service Principal Name — unique identifier for a service instance in AD. Required for Kerberos authentication and Kerberoasting attacks |
| mvindex | SPL function to extract individual values from a multivalue field by position. Used to split Account_Name into actor vs target |
| LSASS | Local Security Authority Subsystem Service — Windows process that stores credentials in memory. Target for credential dumping attacks |
