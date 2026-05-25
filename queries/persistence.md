# Persistence Detection
**MITRE ATT&CK:** [T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
**Detection Event:** EventCode 4698 (Scheduled Task Created), EventCode 7045 (New Service Installed)
**Lab tested:** May 20, 2026 via `Invoke-AtomicTest T1053.005 -TestNumbers 2` (task name: "spawn")
**Prerequisite:** "Audit Other Object Access Events" must be enabled via GPO before EventCode 4698 will appear. See [SETUP.md](../SETUP.md) for configuration steps.

---

## Table of Contents

1. [Scheduled Task Creation](#1-scheduled-task-creation)
2. [New Service Installation](#2-new-service-installation)
3. [PowerShell Execution Process Creation](#3-powershell-execution--process-creation)
4. [PowerShell Evasion Flags](#4-powershell-evasion-flags)

---

## 1. Scheduled Task Creation

Detects new scheduled task creation via EventCode 4698. Attackers use scheduled tasks to maintain persistent code execution a task configured to run at startup, logon, or on a time interval survives reboots and continues executing even if the initial access vector is closed. Look for unexpected task names, tasks created outside of maintenance windows, or tasks created by user accounts rather than SYSTEM.

```spl
index=windows EventCode=4698
| table _time, host, Account_Name, Task_Name
| sort -_time
```

[Back to Table of Contents](#table-of-contents)


## 2. New Service Installation

EventCode 7045 fires when a new service is installed on a Windows system. Services are an alternate persistence mechanism alongside scheduled tasks a malicious service configured to start automatically will survive reboots. Watch for unusual service names, services with paths pointing to temp directories or user profile folders, and services running under unexpected accounts.

```spl
index=windows EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Account
| sort -_time
```

[Back to Table of Contents](#table-of-contents)


## 3. PowerShell Execution Process Creation

Detects PowerShell or cmd.exe process creation via EventCode 4688. Requires "Audit Process Creation" audit policy enabled via GPO. Useful for catching malicious child processes launched from unexpected parents for example, a web server process spawning PowerShell, or a document viewer spawning cmd.exe.

```spl
index=windows EventCode=4688 (New_Process_Name=*powershell* OR New_Process_Name=*cmd*)
| table _time, host, Creator_Process_Name, New_Process_Name, Process_Command_Line
```

[Back to Table of Contents](#table-of-contents)


## 4. PowerShell Evasion Flags

Hunts for common PowerShell obfuscation and execution policy bypass flags in the CommandLine field via Sysmon EventCode 1. These flags are frequently used by attackers to avoid detection and execute code without leaving obvious traces.

| Flag | Purpose | Why Attackers Use It |
|---|---|---|
| `-enc` | Base64 encoded command | Hides the actual command content from casual inspection |
| `-nop` | No profile | Faster, stealthier launch skips profile script execution |
| `bypass` | Execution policy bypass | Explicitly overrides script execution restrictions |
| `IEX` | Invoke-Expression | Downloads and executes code directly in memory without writing to disk |

```spl
index=windows EventCode=1 Image=*powershell*
| search CommandLine=*-enc* OR CommandLine=*-nop* OR CommandLine=*bypass* OR CommandLine=*IEX*
| table _time, host, ParentImage, CommandLine
```

[Back to Table of Contents](#table-of-contents)

---

*Part of the [Cyber Detection Home Lab](https://github.com/netcur10s/soc-lab) query library*
