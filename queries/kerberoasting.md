# Kerberoasting Detection
**MITRE ATT&CK:** [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
**Detection Event:** EventCode 4769 (Kerberos Service Ticket Requested)
**Lab tested:** May 19, 2026 via `Invoke-AtomicTest T1558.003 -TestNumbers 5 -PromptForInputArgs`
**Lab setup:** `svc_sql` service account with SPN `MSSQLSvc/DC01.lab.local:1433`, RC4 forced via `msDS-SupportedEncryptionTypes=4`


## Table of Contents

1. [Kerberoasting Detection RC4 Tickets](#1-kerberoasting-detection-rc4-tickets)
2. [Volume Analysis Multiple RC4 Requests](#2-volume-analysis-multiple-rc4-requests)
3. [Encryption Type Baseline](#3-encryption-type-baseline)
4. [Kerberos TGT Requests Baseline](#4-kerberos-tgt-requests-baseline)


## 1. Kerberoasting Detection RC4 Tickets

The primary Kerberoasting detection query. The key indicator is `Ticket_Encryption_Type=0x17` RC4 encryption. Attack tools request RC4 tickets specifically because RC4 hashes are significantly faster to crack offline than AES. Legitimate modern systems use AES (0x12 or 0x18). Any RC4 service ticket request in an environment that has not explicitly configured RC4 should be treated as suspicious.

```spl
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| table _time, host, Account_Name, Service_Name, Ticket_Encryption_Type
| sort -_time
```

[Back to Table of Contents](#table-of-contents)


## 2. Volume Analysis Multiple RC4 Requests

A single RC4 ticket request could be a legacy compatibility issue. Multiple RC4 requests from the same account in a short window is a much stronger Kerberoasting signal attack tools typically request tickets for every service account with an SPN in a single run.

```spl
index=windows EventCode=4769 Ticket_Encryption_Type=0x17
| eval user=mvindex(Account_Name,0)
| bucket _time span=60s
| stats count by _time, user, host
| where count > 3
| sort -count
```

[Back to Table of Contents](#table-of-contents)


## 3. Encryption Type Baseline

Baselines all Kerberos ticket encryption types across the environment. Run this before deploying the RC4 detection query to understand what encryption types are normal in your environment. If RC4 already appears frequently due to legacy systems, the primary detection query will generate false positives and the threshold on the volume query should be adjusted.

```spl
index=windows EventCode=4769
| stats count by Ticket_Encryption_Type, Account_Name
| sort -count
```

[Back to Table of Contents](#table-of-contents)


## 4. Kerberos TGT Requests Baseline

EventCode 4768 fires when a Kerberos Ticket Granting Ticket is requested the initial authentication step before any service tickets are requested. Useful for baselining normal domain authentication patterns and identifying unusual accounts or off-hours requests.

```spl
index=windows EventCode=4768
| table _time, host, Account_Name, Client_Address
| sort -_time
```

[Back to Table of Contents](#table-of-contents)

---

*Part of the [Cyber Detection Home Lab](https://github.com/netcur10s/soc-lab) query library*
