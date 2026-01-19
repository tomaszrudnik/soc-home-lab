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

---

## Detection Logic

### Sysmon – Process Create (EventCode 1)

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time host User Image ParentImage CommandLine
