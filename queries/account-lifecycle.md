# Account Lifecycle and Backdoor Detection
**MITRE ATT&CK:** [T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
**Detection Events:** EventCode 4720 (account created), 4726 (account deleted), 4732 (member added to group)
**Lab tested:** May 16–19, 2026 via `net user` commands and `Invoke-AtomicTest T1136.001`


## Table of Contents

1. [Account Creation — Clean Field Extraction](#1-account-creation--clean-field-extraction)
2. [Account Deletion](#2-account-deletion)
3. [Backdoor Account and Privilege Escalation — Correlated](#3-backdoor-account-and-privilege-escalation--correlated)
4. [Member Added to Local Administrators Group](#4-member-added-to-local-administrators-group)


## 1. Account Creation — Clean Field Extraction

Detects new local user account creation via EventCode 4720. Account_Name is a multivalue field in Windows Security events `mvindex(Account_Name,0)` extracts the actor who performed the action and `mvindex(Account_Name,1)` extracts the account that was created. Without this extraction, both values stack in the same cell and the output is unreadable.

```spl
index=windows EventCode=4720
| eval Who_Created=mvindex(Account_Name,0)
| eval Account_Created=mvindex(Account_Name,1)
| table _time, host, Who_Created, Account_Created
```

[Back to Table of Contents](#table-of-contents)


## 2. Account Deletion

Detects user account deletion via EventCode 4726. On its own this may be routine — paired with account creation (4720) it shows the full account lifecycle. A rapid create and delete sequence is a red flag indicating an attacker created an account, used it, and cleaned up.

```spl
index=windows EventCode=4726
| eval Who_Deleted=mvindex(Account_Name,0)
| eval Account_Deleted=mvindex(Account_Name,1)
| table _time, host, Who_Deleted, Account_Deleted
```

[Back to Table of Contents](#table-of-contents)


## 3. Backdoor Account and Privilege Escalation — Correlated

Correlates account creation (4720) and group membership changes (4732) in a single query, showing both events side by side ordered by time. This is the key detection for the attacker pattern of: create account → immediately add to Administrators group.

Two field notes:
- `coalesce(Computer, host)` handles the field name difference between DC and workstation events — DCs log to `Computer`, workstations log to `host`
- `Member_Name` in 4732 events may be blank if the SID was not resolved at the time of logging. Use `SAM_Account_Name` from the correlated 4720 event instead

```spl
index=windows (EventCode=4720 OR EventCode=4732)
| eval Computer=coalesce(Computer, host)
| eval EventType=case(EventCode=4720, "Account Created", EventCode=4732, "Added to Administrators")
| table _time, Computer, EventCode, EventType, Account_Name, SAM_Account_Name
| sort _time
```

[Back to Table of Contents](#table-of-contents)


## 4. Member Added to Local Administrators Group

Standalone query for monitoring privilege escalation via group membership changes. EventCode 4732 fires whenever a member is added to any local security-enabled group. Scope this to the Administrators group for highest fidelity alerting.

```spl
index=windows EventCode=4732
| eval Actor=mvindex(Account_Name,0)
| table _time, host, Actor, SAM_Account_Name, Group_Name
| sort -_time
```

[Back to Table of Contents](#table-of-contents)

---

*Part of the [Cyber Detection Home Lab](https://github.com/netcur10s/soc-lab) query library*
