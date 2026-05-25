# Foundational Queries
**Purpose:** First-look and baseline queries for any investigation
**Index:** `index=windows`

---

## Table of Contents

1. [All Events — First Look](#1-all-events--first-look)
2. [All Hosts Logging to Splunk](#2-all-hosts-logging-to-splunk)
3. [Verify Forwarder Connections](#3-verify-forwarder-connections)
4. [All Logons by Host and Type](#4-all-logons-by-host-and-type)
5. [Failed Logons Summary](#5-failed-logons-summary)
6. [Processes Created via Sysmon](#6-processes-created-via-sysmon)
7. [New Scheduled Tasks](#7-new-scheduled-tasks)
8. [New Local Accounts](#8-new-local-accounts)
9. [Events from Last 2 Minutes](#9-events-from-last-2-minutes)

---

## 1. All Events — First Look

Use this to get oriented at the start of any investigation. Returns the 50 most recent events across all indexes.

```spl
index=* | head 50
```

[Back to Table of Contents](#table-of-contents)


## 2. All Hosts Logging to Splunk

Verifies all forwarders are sending data. Run this at the start of a session to confirm all expected hosts are present before hunting.

```spl
index=windows
| stats count by host
| sort -count
```

[Back to Table of Contents](#table-of-contents)


## 3. Verify Forwarder Connections

Checks the last seen time per hostname using Splunk's internal metrics. Useful for diagnosing a host that has stopped forwarding logs without an obvious error.

```spl
index=_internal source=*metrics.log group=tcpin_connections
| stats latest(_time) as last_seen by hostname
```

[Back to Table of Contents](#table-of-contents)


## 4. All Logons by Host and Type

Baselines logon activity across the environment. Understanding normal logon patterns makes anomalies easier to spot. Logon_Type values to know: 2 = Interactive, 3 = Network, 10 = Remote Interactive (RDP).

```spl
index=windows EventCode=4624
| stats count by host, Account_Name, Logon_Type
| sort -count
```

[Back to Table of Contents](#table-of-contents)


## 5. Failed Logons Summary

Quick view of failed authentication attempts across the environment. High counts from a single source address or against a single account warrant closer investigation.

```spl
index=windows EventCode=4625
| stats count by host, Account_Name, Source_Network_Address
| sort -count
```

[Back to Table of Contents](#table-of-contents)


## 6. Processes Created via Sysmon

Primary hunting event for execution detection. Sysmon EventCode 1 captures the full command line, parent process image path, and file hashes significantly richer than EventCode 4688. Run this to see what has been executing across endpoints.

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time, host, Image, ParentImage, CommandLine
```

[Back to Table of Contents](#table-of-contents)


## 7. New Scheduled Tasks

Quick view of any scheduled task creation events. Requires "Audit Other Object Access Events" enabled via GPO. See [SETUP.md](../SETUP.md) for configuration steps.

```spl
index=windows EventCode=4698
| table _time, host, Account_Name, Task_Name
```

[Back to Table of Contents](#table-of-contents)


## 8. New Local Accounts

Shows newly created user accounts. Account_Name is a multivalue field — `mvindex(Account_Name,0)` extracts the actor who created the account and `mvindex(Account_Name,1)` extracts the account that was created.

```spl
index=windows EventCode=4720
| eval Who_Created=mvindex(Account_Name,0)
| eval Account_Created=mvindex(Account_Name,1)
| table _time, host, Who_Created, Account_Created
```

[Back to Table of Contents](#table-of-contents)


## 9. Events from Last 2 Minutes

Real-time view scoped to the last 2 minutes. Use this immediately after running an Atomic Red Team simulation to confirm telemetry is landing in Splunk before running more specific detection queries.

```spl
index=windows
| where _time >= relative_time(now(),"-2m")
| stats count by host, EventCode
| sort host
```

[Back to Table of Contents](#table-of-contents)

---

*Part of the [Cyber Detection Home Lab](https://github.com/netcur10s/soc-lab) query library*
