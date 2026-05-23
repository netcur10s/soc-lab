# Lab Setup Guide
## Cyber Detection Home Lab — Full Build Documentation

This document covers the complete build process for this detection lab from scratch. It is written as a reference for anyone who wants to understand how the environment was built, what decisions were made and why, and how to replicate it. Every configuration step here reflects something I actually ran into, fixed, and verified working.

---

## Table of Contents

1. [Design Decisions and Network Architecture](#1-design-decisions-and-network-architecture)
2. [Prerequisites and Software Versions](#2-prerequisites-and-software-versions)
3. [PFSense Firewall Setup](#3-pfsense-firewall-setup)
4. [Active Directory Domain Build](#4-active-directory-domain-build)
5. [Splunk SIEM Deployment](#5-splunk-siem-deployment)
6. [Sysmon Deployment](#6-sysmon-deployment)
7. [Splunk Universal Forwarder Deployment](#7-splunk-universal-forwarder-deployment)
8. [NTP Time Synchronization](#8-ntp-time-synchronization)
9. [GPO and Audit Policy Configuration](#9-gpo-and-audit-policy-configuration)
10. [Atomic Red Team Installation](#10-atomic-red-team-installation)
11. [Wazuh and Nessus Setup](#11-wazuh-and-nessus-setup)
12. [Troubleshooting Reference](#12-troubleshooting-reference)

---

## 1. Design Decisions and Network Architecture

### Why Four Subnets

The lab is segmented into four isolated subnets rather than one flat network. This was a deliberate design choice for two reasons.

First, it mirrors how real enterprise environments are structured. Production networks separate their endpoints, servers, security tools, and management infrastructure. Learning to work in a segmented environment from the start builds the right mental model.

Second, it creates realistic detection scenarios. When an attacker moves from the Attacker subnet (10.10.40.0/24) to the Active Directory subnet (10.10.10.0/24), that lateral movement crosses a network boundary and generates different telemetry than movement within the same subnet. That distinction matters in real SOC work.

### Subnet Assignment

| Segment | Subnet | Purpose |
|---|---|---|
| Active Directory Lab | 10.10.10.0/24 | Windows domain environment — primary victim network |
| SOC Lab | 10.10.20.0/24 | Detection and analysis tools |
| Vulnerable Machines | 10.10.30.0/24 | Intentionally vulnerable targets |
| Attackers | 10.10.40.0/24 | Offensive platforms |
| WAN / Firewall | 192.168.40.13/24 | PFSense internet gateway |

### Why PFSense as the Firewall

PFSense is free, open source, and widely used in both home lab and production environments. It provides inter-segment routing, NAT for internet access, and a web UI for firewall rule management. It also becomes a log source in later weeks when we add PFSense syslog ingestion into Splunk.

[Back to Table of Contents](#table-of-contents)

---

## 2. Prerequisites and Software Versions

### Hypervisor

This lab runs on Proxmox. All machines are virtual.

### Machine Specifications (Minimum)

| Machine | RAM | Disk | Notes |
|---|---|---|---|
| PFSense | 1 GB | 20 GB | Runs lean — 1 GB is sufficient |
| WS01 | 4 GB | 60 GB | Needs headroom for Sysmon and ART |
| WS02 | 4 GB | 60 GB | Standard Windows endpoint |
| DC01 | 4 GB | 60 GB | Windows Server with AD DS role |
| Splunk | 8 GB | 100 GB | Index storage grows quickly |
| Nessus | 4 GB | 40 GB | |
| Wazuh | 4 GB | 50 GB | |
| Kali Linux | 4 GB | 60 GB | |
| Parrot OS | 4 GB | 60 GB | |

### Software Versions Used

| Software | Version | Source |
|---|---|---|
| PFSense | 2.7.x | https://www.pfsense.org/download/ |
| Windows Server | 2022 Evaluation | https://www.microsoft.com/en-us/evalcenter/ |
| Windows | 11 Evaluation | https://www.microsoft.com/en-us/evalcenter/ |
| Splunk Enterprise | 10.x | https://www.splunk.com/en_us/download.html |
| Splunk Universal Forwarder | 10.x (must match Splunk version) | https://www.splunk.com/en_us/download/universal-forwarder.html |
| Sysmon | Latest | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon |
| Atomic Red Team | Latest | https://github.com/redcanaryco/atomic-red-team |
| Nessus Essentials | Latest (free tier) | https://www.tenable.com/products/nessus/nessus-essentials |
| Wazuh | 4.x | https://wazuh.com/install/ |
| Kali Linux | Latest rolling | https://www.kali.org/get-kali/ |
| Parrot OS | Latest | https://www.parrotsec.org/download/ |

[Back to Table of Contents](#table-of-contents)

---

## 3. PFSense Firewall Setup

PFSense is the first machine to build because everything else routes through it.

### Installation

1. Download the PFSense ISO from the official site
2. Create a new VM with two network adapters:
   - Adapter 1: Bridged (connects to your home network for internet access)
   - Adapter 2: Host-only or internal network (LAN side)
3. Boot from the ISO and follow the installer — defaults are fine
4. On first boot, assign interfaces when prompted:
   - WAN: the bridged adapter
   - LAN: the host-only adapter

### Adding Additional Interfaces

Each subnet needs its own interface in PFSense.

1. Log into the PFSense web UI at http://192.168.40.13
2. Navigate to Interfaces, then Assignments
3. Add interfaces for each additional VMware virtual network adapter
4. Assign and configure each:
   - OPT1: 10.10.10.254/24 (Active Directory Lab gateway)
   - OPT2: 10.10.20.254/24 (SOC Lab gateway)
   - OPT3: 10.10.30.254/24 (Vulnerable Machines gateway)
   - OPT4: 10.10.40.254/24 (Attackers gateway)

### Firewall Rules

For the lab to function, traffic needs to flow between subnets. Add allow rules on each interface that permit traffic to other subnets. In a production environment these rules would be far more restrictive — for lab purposes, allow rules are acceptable while you focus on detection skills rather than firewall policy.

### NTP Server Configuration

PFSense acts as the NTP server for the entire lab. This is important — all machines need synchronized time or Splunk log correlation breaks.

1. Navigate to Services, then NTP
2. Enable NTP server
3. Note the PFSense LAN IP (10.10.10.254 or whichever subnet interface you configure as primary)
4. All Windows machines will point to this address for time sync

[Back to Table of Contents](#table-of-contents)

---

## 4. Active Directory Domain Build

### DC01 — Domain Controller

DC01 runs Windows Server 2019 and hosts the lab.local Active Directory domain.

**Initial setup:**
1. Install Windows Server 2019 with Desktop Experience
2. Set static IP: 10.10.10.3, subnet 255.255.255.0, gateway 10.10.10.254, DNS 127.0.0.1
3. Rename the computer to DC01 before promoting to domain controller

**Promote to Domain Controller:**
1. Open Server Manager, click Add Roles and Features
2. Select Active Directory Domain Services
3. After installation, click the notification flag and select Promote this server to a domain controller
4. Choose Add a new forest
5. Root domain name: lab.local
6. Set DSRM password and complete the wizard
7. Server will reboot — log in with LAB\Administrator

**Create Domain User Accounts:**

These accounts are used throughout the lab for attack simulation and detection.

```powershell
# Run on DC01 as Administrator
New-ADUser -Name "John Smith" -SamAccountName "jsmith" -UserPrincipalName "jsmith@lab.local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

New-ADUser -Name "Jane Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@lab.local" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
```

**Create Kerberoastable Service Account:**

This account is created specifically to practice detecting Kerberoasting attacks. RC4 encryption is forced because it produces the detectable 0x17 encryption type in EventCode 4769.

```powershell
# Create the service account
New-ADUser -Name "SQL Service" -SamAccountName "svc_sql" -UserPrincipalName "svc_sql@lab.local" -AccountPassword (ConvertTo-SecureString "Service@123!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true

# Register the SPN so Kerberos tickets can be requested for it
setspn -A MSSQLSvc/DC01.lab.local:1433 svc_sql

# Force RC4 encryption only (makes Kerberoasting detectable via 0x17)
Set-ADUser svc_sql -Replace @{msDS-SupportedEncryptionTypes=4}
```

### WS01 and WS02 — Workstations

1. Install Windows 10 or 11
2. Set static IPs:
   - WS01: 10.10.10.1, gateway 10.10.10.254, DNS 10.10.10.3 (DC01)
   - WS02: 10.10.10.2, gateway 10.10.10.254, DNS 10.10.10.3 (DC01)
3. Rename computers to WS01 and WS02 respectively
4. Join the lab.local domain:
   - Right-click Start, System, Domain or workgroup
   - Change, Domain: lab.local
   - Authenticate with LAB\Administrator
   - Reboot


[Back to Table of Contents](#table-of-contents)
---

## 5. Splunk SIEM Deployment

Splunk is the central detection platform. All logs flow here.

### Installation

1. Download Splunk Enterprise from splunk.com (free trial license supports up to 500MB/day)
2. Install on the Splunk VM (10.10.20.3)
3. During installation, set admin credentials — keep these secure
4. Splunk web UI runs at http://10.10.20.3:8000

### Configure Receiving Port

Splunk must listen for incoming data from forwarders.

1. Log into Splunk web UI
2. Navigate to Settings, then Forwarding and Receiving
3. Under Receive Data, click Add New
4. Port: 9997
5. Save

### Create the Windows Index

Events from Windows machines should land in a dedicated index, not the default `main` index.

1. Navigate to Settings, then Indexes
2. Click New Index
3. Index name: windows
4. Leave other settings as default
5. Save

**Why this matters:** If you skip this step and events land in `main`, all your SPL queries using `index=windows` will return nothing. This was one of the first issues encountered in the lab — resolved by creating the index and correcting the forwarder configuration.


[Back to Table of Contents](#table-of-contents)
---

## 6. Sysmon Deployment

Sysmon provides enhanced telemetry that Windows Security events alone cannot. It captures full command lines, parent-child process relationships, network connections, and file creation events.

### Installation (Run on WS01, WS02, and DC01)

1. Download Sysmon from Microsoft Sysinternals
2. Download a Sysmon configuration file — the SwiftOnSecurity config is a good starting point:
   https://github.com/SwiftOnSecurity/sysmon-config

3. Install Sysmon with the config:
```cmd
sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Fix: Sysmon Access Denied (errorCode=5)

If Sysmon events show errorCode=5 in Splunk, the Splunk Universal Forwarder does not have permission to read the Sysmon event log channel.

**Root cause:** The forwarder is running as a restricted service account that cannot access the Microsoft-Windows-Sysmon/Operational log.

**Fix:** Change the forwarder service to run as LocalSystem.

```cmd
# Run in cmd.exe as Administrator on the affected machine
sc config SplunkForwarder obj= LocalSystem
net stop SplunkForwarder
net start SplunkForwarder
```

After restarting, Sysmon events will appear in Splunk under source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.


[Back to Table of Contents](#table-of-contents)
---

## 7. Splunk Universal Forwarder Deployment

The Universal Forwarder collects logs from each Windows machine and sends them to Splunk.

### Installation (Repeat on WS01, WS02, DC01)

1. Download the Splunk Universal Forwarder from splunk.com
2. Run the installer as Administrator
3. During installation:
   - Deployment server: leave blank
   - Receiving indexer: 10.10.20.3, port 9997

### Configure inputs.conf

After installation, configure which logs to forward. Create or edit this file on each machine:

**Path:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Security]
index = windows
disabled = 0
renderXml = true
checkpointInterval = 5

[WinEventLog://System]
index = windows
disabled = 0
renderXml = true

[WinEventLog://Application]
index = windows
disabled = 0
renderXml = true

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = windows
disabled = 0
renderXml = true
checkpointInterval = 5
```

Restart the forwarder after saving:
```cmd
net stop SplunkForwarder && net start SplunkForwarder
```

### Fix: Index Routing — Events Landing in Main Instead of Windows

**Root cause:** A competing `inputs.conf` file exists elsewhere in the forwarder directory hierarchy that does not specify `index = windows`, so events fall back to the default `main` index.

**Fix:** Find the conflicting file and either remove it or rename it to `.bak`:

```cmd
# Search for competing inputs.conf files
dir /s "C:\Program Files\SplunkUniversalForwarder\*.conf" | findstr inputs
```

Rename any conflicting file:
```cmd
rename "C:\Program Files\SplunkUniversalForwarder\etc\apps\SomeApp\local\inputs.conf" inputs.conf.bak
```

Restart the forwarder and verify events land in `index=windows`.


[Back to Table of Contents](#table-of-contents)
---

## 8. NTP Time Synchronization

Clock skew between machines causes significant problems in Splunk. Events appear to arrive out of order or with future timestamps, making correlation impossible. This is not immediately obvious as a root cause when you first see it.

### NTP Hierarchy

```
Internet NTP servers
        |
   PFSense (NTP server for the lab)
        |
      DC01 (NTP server for domain members)
        |
   WS01, WS02 (sync to DC01 via domain policy)
```

### Configure DC01 to Sync with PFSense

```cmd
# Run on DC01 as Administrator
w32tm /config /manualpeerlist:10.10.10.254 /syncfromflags:manual /reliable:yes /update
net stop w32tm && net start w32tm
w32tm /resync
```

### Configure Workstations

Domain-joined workstations automatically sync to DC01 via Windows Time Service. If a machine is not syncing:

```cmd
w32tm /resync /force
w32tm /query /status
```

### Fix: Log Delays in Splunk

**Root cause:** Clock skew between machines causes Splunk to index events with incorrect timestamps, making recent events appear to arrive late or not at all in real-time searches.

**Fix:** Sync all machines to PFSense via w32tm as above. Also add `checkpointInterval=5` to inputs.conf on each forwarder — this reduces the checkpoint write interval and ensures the forwarder picks up new events more frequently.


[Back to Table of Contents](#table-of-contents)
---

## 9. GPO and Audit Policy Configuration

Windows does not log many security-relevant events by default. Audit policy must be explicitly enabled, and Group Policy is the correct way to enforce it consistently across all domain machines.

### Open Group Policy Management

On DC01, open Group Policy Management Console (gpmc.msc). Edit the Default Domain Policy.

### Audit Policy Settings

Navigate to:
`Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies`

Configure the following:

| Category | Subcategory | Setting |
|---|---|---|
| Account Logon | Kerberos Authentication Service | Success and Failure |
| Account Logon | Kerberos Service Ticket Operations | Success and Failure |
| Account Logon | Credential Validation | Success and Failure |
| Account Management | User Account Management | Success and Failure |
| Account Management | Security Group Management | Success and Failure |
| Account Management | Computer Account Management | Success and Failure |
| DS Access | Directory Service Access | Success and Failure |
| Detailed Tracking | Process Creation | Success |
| Policy Change | Audit Policy Change | Success and Failure |
| Object Access | Other Object Access Events | Success and Failure |

**Why "Other Object Access Events" matters:** This subcategory is required for EventCode 4698 (scheduled task created) to appear. It is not enabled by default and is a common reason scheduled task detection fails.

### Restricted Groups GPO — Local Administrator Management

This GPO enforces which domain accounts are in the local Administrators group on workstations.

1. Create a new GPO called Restricted Groups — Workstations
2. Navigate to: `Computer Configuration > Policies > Windows Settings > Security Settings > Restricted Groups`
3. Add `Administrators` as the group
4. Add `jsmith` and `jdoe` as members
5. Link the GPO to the workstations OU

### Apply GPO Changes

After modifying any GPO, force an update on target machines:

```cmd
# Run on each workstation
gpupdate /force
```

### Fix: EventCode 4720 Not Appearing in Splunk

**Root cause:** User Account Management auditing is not enabled.

**Fix:** Enable it via GPO as described above under Audit Policy Settings, then run `gpupdate /force` on all affected machines.

### Fix: EventCode 4698 Not Appearing in Splunk

**Root cause:** "Audit Other Object Access Events" is not enabled.

**Fix:** Enable it via GPO under Object Access subcategory, then run `gpupdate /force`.

### Fix: Splunk 4625 Events Not Appearing From Offline Machines

**Root cause:** The Splunk forwarder service account (jsmith in this lab) lacks permission to read the Security event log.

**Fix:** Add the service account to the Event Log Readers group on DC01.

```powershell
# Run on DC01 as Administrator
Add-ADGroupMember -Identity "Event Log Readers" -Members "jsmith"
```

Then run `gpupdate /force` on the affected workstation.


[Back to Table of Contents](#table-of-contents)
---

## 10. Atomic Red Team Installation

Atomic Red Team (ART) is an open-source library of small, atomic attack simulations mapped to MITRE ATT&CK techniques. It runs on WS01 and generates real attack telemetry for detection practice.

### Installation

```powershell
# Run in PowerShell as Administrator on WS01

# Set execution policy for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Install the ART framework
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force

# Install the atomic test library
Install-AtomicRedTeam -getAtomics -Force

# Import the module
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
```

### Make ART Load Automatically

To avoid re-importing the module every session, add it to your PowerShell profile:

```powershell
# Check if profile exists, create if not
if (!(Test-Path $PROFILE)) { New-Item -Path $PROFILE -ItemType File -Force }

# Add import line to profile
Add-Content $PROFILE "`nImport-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force"
```

### Basic Usage

```powershell
# Run a technique (example: PowerShell execution)
Invoke-AtomicTest T1059.001 -TestNumbers 1

# List all tests for a technique
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Install prerequisites before running
Invoke-AtomicTest T1059.001 -GetPrereqs

# Clean up after a test
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

### Fix: ART Returns 0 Applicable Tests

**Root cause:** The atomic test library is not installed or is corrupted.

**Fix:** Reinstall the library:
```powershell
Install-AtomicRedTeam -getAtomics -Force
```

If internet access is unavailable from WS01, the powershell-yaml module can be saved on another machine and copied manually:

```powershell
# On a machine with internet access
Save-Module powershell-yaml -Path C:\Temp\

# Copy the folder to WS01
# Destination: C:\Program Files\WindowsPowerShell\Modules\powershell-yaml\
```

### Fix: PowerShell Execution Policy Blocking ART Scripts

When starting a new PowerShell session before running ART tests:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

Use `-Scope Process` so the change only applies to the current session and does not permanently alter the machine's security posture. When prompted to confirm, select Y (Yes) rather than A (Yes to All) — being deliberate about what you confirm is a good habit to build.


[Back to Table of Contents](#table-of-contents)
---

## 11. Wazuh and Nessus Setup

### Nessus Essentials

1. Register for a free Nessus Essentials license at https://www.tenable.com/products/nessus/nessus-essentials
2. Download and install on the Nessus VM (10.10.20.6)
3. Access via https://10.10.20.6:8834
4. Use Nessus to scan the vulnerable machines subnet (10.10.30.0/24) to understand the attack surface before exploitation practice

### Wazuh

Wazuh provides host-based intrusion detection and endpoint log forwarding as a complement to Splunk.

1. Install Wazuh server on the Wazuh VM (10.10.20.5) following the official documentation at https://wazuh.com/install/
2. Install Wazuh agents on WS01, WS02, and DC01
3. Wazuh agent to Splunk integration is configured in a later week — the initial setup just establishes agent connectivity


[Back to Table of Contents](#table-of-contents)
---

## 12. Troubleshooting Reference

A complete troubleshooting log of every issue encountered during this build, with root cause and fix documented.

| Issue | Root Cause | Fix |
|---|---|---|
| Events landing in main index instead of windows | Competing inputs.conf without index specification | Rename conflicting file to .bak or apply server-side transforms.conf routing |
| Sysmon errorCode=5 access denied | Forwarder running as restricted service account | Run `sc config SplunkForwarder obj= LocalSystem` as Administrator, restart service |
| Log delays in Splunk | Clock skew between machines | Sync all machines to PFSense via w32tm, add checkpointInterval=5 to inputs.conf |
| NTPsec not syncing | tos minclock 4 requires 4 NTP sources | Change to `tos minclock 1 minsane 1` in /etc/ntpsec/ntp.conf |
| ART returns 0 applicable tests | Test library not installed or corrupted | Run Install-AtomicRedTeam -getAtomics -Force |
| EventCode 4720 not appearing | User Account Management auditing not enabled | Enable via GPO, run gpupdate /force |
| EventCode 4698 not appearing | Audit Other Object Access Events not enabled | Enable via GPO under Object Access, run gpupdate /force |
| 4732 Member_Name field blank | SID not resolved when account was created rapidly | Correlate with 4720 using SAM_Account_Name instead of Member_Name |
| powershell-yaml module missing | Module not installed on WS01 | Save-Module on another machine, copy to C:\Program Files\WindowsPowerShell\Modules\ |
| 4625 events not appearing from DC01 | Forwarder service account lacks Security log read permission | Add account to Event Log Readers group on DC01 via PowerShell, run gpupdate /force |
| Kerberoasting 4769 events not appearing | No SPNs registered in domain | Create svc_sql with SPN MSSQLSvc/DC01.lab.local:1433, set msDS-SupportedEncryptionTypes=4 |
| Account_Name shows two values stacked | Multivalue field — Splunk maps subject and target to same field | Use mvindex(Account_Name,0) for actor, mvindex(Account_Name,1) for target |
| T1003.001 no telemetry in Splunk | Sysmon EventCode 10 not configured for LSASS | Requires explicit Sysmon config for TargetImage=lsass.exe — revisit in Week 6 |

[Back to Table of Contents](#table-of-contents)

---

*This document is part of the Cyber Detection Home Lab portfolio. See [README.md](README.md) for the full lab overview.*