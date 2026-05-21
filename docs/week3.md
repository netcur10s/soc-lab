## Week 3 Detail — Completed ✓

| **Field** | **Detail** |
| --- | --- |
| Difficulty | Beginner-Intermediate |
| Status | ✓ Completed |
| Date started | May 19, 2026 |
| Date completed | May 20, 2026 |
| Confidence after | 5/10 — AD attack detection complete. Built 5-panel dashboard, detected Kerberoasting, lateral movement, scheduled task persistence. Learned LSASS detection requirements for future. |

**Tasks completed:**

✓  Created svc_sql Kerberoastable service account on DC01 (SPN: MSSQLSvc/DC-01.lab.local:1433, RC4 forced)

✓  Ran ART T1558.003 — detected Kerberoasting via EventCode=4769 + Ticket_Encryption_Type=0x17

✓  Ran ART T1021.002 — detected lateral movement via EventCode=4624 Logon_Type=3

✓  Built AD Health Monitor dashboard in Splunk (5 panels total)

✓  Fixed dashboard field typos (Account_Name, Service_Name, Who_Created)

✓  Enabled "Audit Other Object Access Events" via GPO for EventCode 4698

✓  Ran ART T1053.005-2 — detected scheduled task creation via EventCode 4698 (task name: "spawn")

✓  Added 5th panel to dashboard: Scheduled Tasks Created

✓  Attempted T1003.001 LSASS dump — test succeeded (comsvcs.dll method) but no Sysmon telemetry captured

✓  Documented LSASS detection theory — requires Sysmon EventCode 10 with advanced config (revisit in Week 6)

**Key learnings:**
- Audit policy must be enabled via GPO or using auditpol command before events appear in logs
- Dashboard field names must match exactly (typos break visualizations)
- Some detections (like LSASS access) require advanced Sysmon configuration
- Correlation queries (4720+4732, 4698) are powerful for catching attack chains

**Deferred to Week 6:**
- T1048.003 DNS exfiltration (advanced Sysmon EventCode 22 analysis)
- Advanced Sysmon EventCode 10 configuration for LSASS detection
- Multi-stage correlation alerting