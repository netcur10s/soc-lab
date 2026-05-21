## Week 2 Detail — Completed ✓

| **Field** | **Detail** |
| --- | --- |
| Difficulty | Beginner |
| Status | ✓ Completed |
| Date started | May 16, 2026 |
| Date completed | May 19, 2026 |
| Confidence after | 4/10 — GPO, audit policy, SPL detection queries, Splunk alerting, and AD attack detection completed. |

**Tasks completed:**

✓  Built Windows Event ID cheat sheet — all 8 core IDs documented with notes

✓  Simulated brute force with ART T1110.001 — detected via EventCode=4625

✓  Analysed Sub_Status codes: 0xC0000064 (username enumeration) vs 0xC000006A (credential attack)

✓  Pushed domain-wide audit policy via GPO from DC01

✓  Configured Restricted Groups GPO — jsmith and jdoe added to local Administrators on WS01

✓  Simulated backdoor account creation via net user commands as jsmith

✓  Detected 4720 (account created) and 4732 (added to Administrators) in Splunk

✓  Built correlated 4720+4732 detection query using coalesce and eval

✓  Created real-time Splunk alert — High severity, throttled 60s by Computer

✓  Fixed Splunk forwarder permissions — jsmith added to Event Log Readers via DC01

✓  Configured full audit policy on DC01 — Kerberos, Credential Validation, DS Access, Account Management