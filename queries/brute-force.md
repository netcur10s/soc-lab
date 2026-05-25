# Brute Force Detection
**MITRE ATT&CK:** [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
**Detection Event:** EventCode 4625 (Failed Logon)
**Lab tested:** May 19, 2026 via `Invoke-AtomicTest T1110.001`

---

## Table of Contents

1. [Brute Force — 5+ Failures in 60 Seconds](#1-brute-force--5-failures-in-60-seconds)
2. [Sub_Status Analysis](#2-substatus-analysis)
3. [Failed Logon Volume Over Time](#3-failed-logon-volume-over-time)

---

## 1. Brute Force — 5+ Failures in 60 Seconds

Buckets events into 60-second windows and flags any account or source address generating 5 or more failures within the same window. The threshold of 5 in 60 seconds is a starting point — tune up or down based on your environment's baseline noise.

`mvindex(Account_Name,1)` extracts the target account from the multivalue Account_Name field. Without this, both the actor and target values stack in the same cell.

```spl
index=windows EventCode=4625
| eval user=mvindex(Account_Name,1)
| bucket _time span=60s
| stats count by _time, user, Source_Network_Address, host
| where count >= 5
| sort -count
```

[Back to Table of Contents](#table-of-contents)


## 2. Sub_Status Analysis

Sub_Status tells you what is actually happening behind the failed logon — whether the attacker is enumerating usernames or spraying passwords against known accounts. This distinction changes your response priority.

| Sub_Status | Meaning | Threat Signal |
|---|---|---|
| 0xC0000064 | Username does not exist | Attacker is enumerating valid usernames |
| 0xC000006A | Wrong password for valid account | Attacker has valid usernames and is guessing passwords |

```spl
index=windows EventCode=4625
| eval user=mvindex(Account_Name,1)
| table _time, user, Source_Network_Address, Sub_Status
| sort -_time
```

[Back to Table of Contents](#table-of-contents)


## 3. Failed Logon Volume Over Time

Visualizes failed logon activity as a timechart, making brute force spikes immediately visible. Use this in a dashboard panel alongside the threshold query above for full visibility.

```spl
index=windows EventCode=4625
| eval user=mvindex(Account_Name,1)
| timechart span=5m count by user
```

[Back to Table of Contents](#table-of-contents)

---

*Part of the [Cyber Detection Home Lab](https://github.com/netcur10s/soc-lab) query library*
