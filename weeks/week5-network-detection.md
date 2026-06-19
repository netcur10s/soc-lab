# Week 5: Network Detection & PFSense Analysis

**Date:** June 7, 2026  
**Difficulty:** Intermediate  
**Duration:** ~3 hours  

## What This Week Demonstrates
- Detected port scanning and host discovery using frequency analysis on PFSense firewall logs
- Identified C2 beaconing through connection consistency patterns rather than volume thresholds
- Built custom field extraction for PFSense filterlog after the standard add-on failed to parse correctly
- Filtered infrastructure noise from results to eliminate false positives before tuning alert thresholds
- Built a 4-panel Network Activity Monitor dashboard covering scans, sweeps, and beaconing in real time

## Overview

Week 5 focuses on **network-layer threat detection** using PFSense firewall logs. We detect port scans, host discovery sweeps, DNS exfiltration, and C2 beaconing through frequency analysis and behavioral anomalies.

**Key Outcome:** Detect T1046 (port scans), T1018 (host discovery), T1048.003 (DNS exfiltration), T1071.001 (C2 beaconing) from network traffic alone.

## PFSense Filterlog Format

```
rule,interface,reason,action,direction,ip_version,protocol,src_ip,dst_ip,src_port,dst_port
```

**Example:**
```
262,igb0,match,pass,in,4,tcp,192.168.1.100,10.10.10.1,51234,22
```

**Parsing Challenge:** TA-pfsense didn't parse this format correctly; created custom field extraction.

## Tasks Completed

### Task 1: Establish PFSense Filterlog Baseline

**Verification:**
```spl
index=pfsense | stats count
```

**Result:** 333K events in baseline window; healthy pipeline

**Baseline Pattern:**
- Internal traffic (10.x.x.x ↔ 10.x.x.x): action=pass (allowed by firewall rules)
- DNS (10.x.x.x → 8.8.8.8): action=block (expected; DNS rules restrictive)
- Most traffic: count=1 (individual events, not scans)

### Task 2: Detect Network Service Discovery / Port Scans (T1046)

**Attack Simulation:**
```bash
# From Kali (10.10.40.1), Nmap SYN scan of WS01 (10.10.10.1)
nmap -sS 10.10.10.1 -p 1-10000
# Result: 1002 unique ports scanned in 60 seconds
```

**Detection Query:**
```spl
index=pfsense 
| bucket _time span=60s 
| stats dc(dst_port) as unique_ports by _time, src_ip, dst_ip, action 
| where unique_ports >= 15 
| sort -unique_ports
```

**Logic:**
1. Bucket events into 60-second windows
2. Count unique destination ports per source-destination pair
3. Flag if 15+ unique ports (normal traffic rarely hits multiple ports)
4. Result: 1002 ports detected; clear port scan pattern

**Threshold Tuning:**
- 15+ ports = suspected scan (triggers)
- 5-15 ports = possible port scan (investigate)
- <5 ports = normal (no alert)

**Result:** ✅ Detected 1002 unique ports in 60 seconds from single source

**Port Scan Detection:**

![Nmap SYN Scan in Progress](./screenshots/week5-01-nmap-syn-scan.png)
*Nmap SYN scan (-sS) running from Kali against WS01 targeting ports 1-10000*

![Splunk Port Scan Detection - 1002 Unique Ports](./screenshots/week5-02-port-scan-detection.png)
*Splunk showing dc(dst_port)=1002 in 60-second window - clear port scanning pattern detected*

### Task 3: Detect Remote System Discovery / Host Sweep (T1018)

**Attack Simulation:**
```bash
# From Kali, ping sweep of all four lab subnets
nmap -sn 10.10.10.0/24 10.10.20.0/24 10.10.30.0/24 10.10.40.0/24
# Result: 765 unique IPs discovered
```

**Detection Query:**
```spl
index=pfsense 
| bucket _time span=60s 
| stats dc(dst_ip) as unique_ips by _time, src_ip, action 
| where unique_ips >= 15 
| search NOT src_ip=192.168.40.13 
| sort -unique_ips
```

**Filtering Home Router Noise:**
- UDM Pro at 192.168.40.13 periodically scans network
- Added exclusion: `NOT src_ip=192.168.40.13`
- Result: Clean detection of attacker sweep, no false positives

**Result:** ✅ Detected 765 unique IPs from single source (clear host discovery pattern)

**Host Sweep Detection:**

![Nmap Ping Sweep Command](./screenshots/week5-03-nmap-ping-sweep.png)
*Nmap ping sweep (-sn) running across all four lab subnets (10.10.10.0, 10.10.20.0, 10.10.30.0, 10.10.40.0)*

![Splunk Host Sweep Detection - 765 Unique IPs](./screenshots/week5-04-host-sweep-detection.png)
*Splunk showing dc(dst_ip)=765 in 60-second window from single source - flagged after filtering UDM Pro infrastructure noise*

### Task 4: Detect C2 Beaconing / Command and Control (T1071.001)

**Attack Simulation:**
```bash
# From Kali (10.10.40.1), curl loop to WS01 (10.10.10.1) every 15 seconds
while true; do curl http://10.10.10.1:80/callback -m 2; sleep 15; done
# 17 connections in 5-minute window
```

**Pattern:** Same source → destination → port at consistent intervals = beaconing

**Detection Query:**
```spl
index=pfsense action=pass 
| bucket _time span=5m 
| stats count by _time, src_ip, dst_ip, dst_port 
| where count >= 10 
| search NOT src_ip=192.168.40.13 
| sort -count
```

**Logic:**
1. Bucket into 5-minute windows
2. Count connections per src-dst-port triplet
3. Flag if 10+ connections in that window (consistent beaconing)
4. Exclude known infrastructure noise

**Result:** ✅ Detected 17 connections every 15 seconds; clear C2 beacon pattern

**Key Insight:** Beaconing is detected by **consistency**, not volume. 17 connections is low traffic but regular = suspicious.

**C2 Beaconing Detection:**

![Curl Loop C2 Simulation](./screenshots/week5-05-curl-c2-loop.png)
*Terminal showing curl loop: `while true; do curl http://10.10.10.1:80/callback; sleep 15; done` - C2 callback every 15 seconds*

![Splunk C2 Beaconing Pattern](./screenshots/week5-06-c2-beaconing.png)
*Splunk showing count=17 connections same src-dst-port in 5m window with consistent 15-second intervals*

### Task 5: Build Network Activity Monitor Dashboard

**4-Panel Dashboard:**

1. **C2 Beaconing Candidates** — Connections with count >= 10 in 5m windows
2. **Port Scan Detection** — dc(dst_port) >= 15 in 60s windows
3. **Host Sweep Detection** — dc(dst_ip) >= 15 in 60s windows
4. **Top Talkers (Outbound)** — Highest-volume source IPs outbound

**Dashboard Purpose:** Operations team monitors network threats in real-time; anomalies immediate visible

**Result:** ✅ Professional dashboard ready for SOC analyst use

**Dashboard Evidence:**

![Network Activity Monitor - All 4 Panels](./screenshots/week5-07-network-monitor-dashboard.png)
*Splunk Network Activity Monitor dashboard showing all 4 panels live - C2 Beaconing Candidates, Port Scan Detection, Host Sweep Detection, Top Talkers*

![C2 Beaconing Panel - Malicious Source Highlighted](./screenshots/week5-08-c2-panel-malicious.png)
*C2 Beaconing panel zoomed in showing detected malicious source IP (10.10.40.1 Kali) with regular connection pattern*

![Port Scan Panel - 1002 Unique Ports](./screenshots/week5-09-port-scan-panel.png)
*Port Scan Detection panel showing dc(dst_port)=1002 from Nmap attack - clear anomaly spike*

### Task 6: Key Observation: DHCP Attribution Issue

**Finding:** Historical logs show scans from 10.10.20.50 (wrong subnet) but Kali is at 10.10.40.1

**Root Cause:** DHCP lease history; old logs still reference old IP

**Lesson:** Correlate DHCP logs when investigating historical network events; IPs can change mid-investigation

## Key Learnings

- **Frequency is the detection lever for network anomalies:** Volume alone isn't suspicious (legitimate bulk transfers); regularity + consistency + unexpected destination = C2
- **Firewall rules don't block internal lateral scanning:** PFSense allows internal traffic (action=pass); detection is the only control
- **Baselining infrastructure noise prevents false positives:** UDM Pro scanning network could have triggered alerts without exclusion rules
- **Custom field extraction beats add-ons when they fail:** TA-pfsense didn't work; custom REPORT= extractor was faster than debugging
- **Host discovery and port scans are distinct patterns:** Host sweep = many IPs; port scan = many ports; both use frequency analysis but different fields

## Splunk Queries Built

| Detection | Query | Confidence |
|---|---|---|
| Port Scan (15+ ports/60s) | dc(dst_port) >= 15 | High |
| Host Sweep (15+ IPs/60s) | dc(dst_ip) >= 15 | High |
| C2 Beaconing (10+ connections/5m) | count >= 10 with regular intervals | Very High |

**Week 5 Status:** ✅ COMPLETE  

## Navigation

← [Back to Main SOC Lab Overview](../Readme.md)  
[Week 6: Threat Hunting →](./week6-threat-hunting.md)