# Detection: Suspicious Process Execution

## Description
This detection focuses on identifying suspicious process executions on Windows endpoints.
It uses Sysmon and Windows Security logs as a baseline SOC L1 detection for triage and investigation.

The goal is to provide visibility into process creation activity and allow analysts to quickly identify:
- unusual binaries
- suspicious execution paths
- abnormal parent-child relationships
- potential post-compromise activity

---

## Data Sources

### Sysmon
- Log source: Microsoft-Windows-Sysmon/Operational
- EventCode: 1 (Process Create)

### Windows Security
- Log source: Security
- EventCode: 4688 (Process Creation)



## Detection Logic

### Sysmon – Process Create (EventCode 1)

```
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time host User Image ParentImage CommandLine
---

### Windows Security – Process Creation (EventCode 4688)

index=windows sourcetype="XmlWinEventLog:Security" EventCode=4688
| search _raw="powershell.exe"
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
| sort -_time


#### Suspicious PowerShell Execution (Obfuscation)

index=windows sourcetype="XmlWinEventLog:Security" EventCode=4688
| search _raw="powershell.exe"
| search _raw="-enc" OR _raw="-encodedcommand" OR _raw="-nop" OR _raw="-w hidden"
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
| sort -_time

#### Suspicious Execution from User Writable Paths

index=windows sourcetype="XmlWinEventLog:Security" EventCode=4688
| search _raw="\\Temp\\" OR _raw="\\AppData\\"
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
| sort -_time

#### Abnormal Parent–Child Process Relationship

index=windows sourcetype="XmlWinEventLog:Security" EventCode=4688
| search _raw="powershell.exe" OR _raw="cmd.exe" OR _raw="mshta.exe" OR _raw="rundll32.exe"
| search ParentProcessName!="C:\\Windows\\System32\\explorer.exe"
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
| sort -_time


## MITRE ATT&CK Mapping

- T1059.001 – Command and Scripting Interpreter: PowerShell
- T1204 – User Execution
- T1036 – Masquerading
- T1106 – Native API

## False Positives

- Administrative PowerShell usage by IT staff
- Legitimate software installers or updaters using PowerShell
- Endpoint management and EDR tools executing PowerShell
- Custom enterprise scripts executed from user writable paths

## Analyst Triage Guidance

1. Review `CommandLine` for obfuscation flags:
   - `-enc`, `-encodedcommand`, `-nop`, `-w hidden`
2. Validate execution path:
   - User-writable paths such as `AppData` or `Temp` increase risk
3. Check parent process legitimacy:
   - `explorer.exe` spawning scripting engines is suspicious
4. Correlate with:
   - User activity
   - Host role
   - Recent alerts on the same endpoint

## Severity and Response

- **Severity**: Medium → High  
- **Escalate to High** if:
  - Encoded PowerShell is used
  - Execution originates from user writable paths
  - Suspicious parent-child relationship is observed

### Recommended Response Actions
- Isolate endpoint if malicious activity is confirmed
- Acquire memory and disk artifacts
- Review additional process activity on the host
- Reset user credentials if compromise is suspected

#### Example Windows Event (4688 – Process Creation)

![Event 4688 XML](../../docs/screenshots/windows/event_4688_process_creation_xml.png)




- 

---
