## Week 1 Detail — Completed ✓

| **Field** | **Detail** |
| --- | --- |
| Difficulty | Beginner |
| Status | ✓ Completed |
| Date started | May 13, 2026 |
| Date completed | May 13, 2026 |
| Confidence after | 3/10 — Can complete tasks with guidance. Improving with repetition. |

**Tasks completed:**

-  Installed Splunk Universal Forwarder on WS01, WS02, DC-01
-  Resolved index routing issue (events landing in main vs windows index)
-  Installed and configured Sysmon on all three Windows endpoint
- Fixed Sysmon errorCode=5 permission issue by running forwarder as LocalSystem
-  Configured NTP hierarchy: PFSense → DC-01 → WS01/WS02
-  Resolved clock skew causing log delays in Splunk
-  Enabled audit process creation on WS01, WS02, DC-01
-  Ran ART T1059.001 and detected it in Splunk via Sysmon EventCode=1
-  Observed Bloodhound/SharpHound AD enumeration telemetry on DC-01
-  Created first Splunk dashboard — Logon Activity

   ![Logon Activity Dashboard](/images/logonactivity.png)