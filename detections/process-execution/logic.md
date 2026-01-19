# Detection: Suspicious Process Execution

## Description
This detection focuses on identifying suspicious process executions on a Windows endpoint using Sysmon data.
It is designed as a baseline SOC L1 detection for triage and investigation.

## Data Source
- Sysmon – Event ID 1 (Process Create)

## Key Fields
- Image
- ParentImage
- CommandLine
- User
- ProcessId
- ParentProcessId

## Analyst Context
This detection is used during initial alert triage to identify unusual binaries, execution paths or abnormal parent-child relationships that may indicate post-compromise activity.
