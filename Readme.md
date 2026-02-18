# 🖥️ SOC Lab Exercises

A collection of blue team exercises conducted in my home SOC lab environment. 
Each exercise simulates real-world threat scenarios and is documented using 
SOC-style workflows — from initial alert through investigation and response.

## 📋 About This Repo

These exercises are designed to build practical SOC analyst skills including 
log analysis, threat detection, alert triage, and incident documentation. 
Write-ups are structured to mirror how findings would be communicated in a 
professional SOC environment.

## 📂 Exercises

| Exercise | Scenario | Tools Used | Difficulty |
|----------|----------|------------|------------|
| [Brute Force Detection](./brute-force-detection) | Detecting credential attacks via Windows event logs | Splunk | Beginner |

*More exercises added regularly.*

## 🛠️ Lab Environment

- **SIEM:** Splunk
- **Log Sources:** Windows Event Logs, Sysmon, Network Logs
- **OS:** Windows Server, Linux
- **Tools:** Nmap, Wireshark, Metasploit

## 📝 Write-Up Structure

Each exercise follows this format:
- **Objective** — What the exercise is designed to detect or investigate
- **Setup** — How the environment and scenario were configured
- **Investigation** — Step-by-step methodology and queries
- **Findings** — What was discovered and indicators of compromise
- **Incident Report** — Summary written as a formal SOC report
- **Detection Rule** — SPL alert that would catch this in a live environment
- **Lessons Learned** — Defensive takeaways

## 🎯 Focus Areas

- Threat detection and alert triage
- Log analysis and correlation
- Incident investigation and documentation
- Detection rule development

## 📫 Connect

- **LinkedIn:** [linkedin.com/in/vic1101](https://linkedin.com/in/vic1101)
- **Email:** v.echevarria@proton.me
