# SOC Home Lab – Splunk SIEM (Junior SOC Analyst L1)

This repository documents a self-built **SOC Home Lab** focused on **SIEM operations, log analysis, alert triage and basic incident response**.
The project is designed to demonstrate hands-on skills required for a **Junior SOC Analyst (L1)** role in a defensive (Blue Team) context.

The lab follows a realistic workflow:
**attack simulation → detection → analysis → triage → response**

---

## Lab Architecture
- **Ubuntu Server** – Splunk SIEM
- **Windows 10** – monitored endpoint (Security + Sysmon logs)
- **Kali Linux** – attack simulation host
- Virtualization: **VirtualBox**

All security-related logs from the Windows endpoint are centrally collected and analyzed in **Splunk SIEM**.

---

## Scope (SOC L1)
- Collection and analysis of Windows security logs
- Sysmon-based visibility into process, network and execution events
- Detection of suspicious post-compromise activity
- Alert triage and basic incident response (L1)
- Incident documentation and escalation decisions
- Mapping detections to **MITRE ATT&CK**
- SOC dashboards for rapid alert triage and visibility


---

## Simulated Incident (High-Level)
A controlled attack scenario is executed in the lab to simulate a compromised Windows endpoint.
The focus of this project is **not exploitation**, but **detection, investigation and response** from a SOC perspective.

Details of the scenario and analysis are documented in the `docs/` directory.

---

## What This Project Demonstrates
- Practical SIEM usage (Splunk)
- Log correlation and investigation
- SOC L1 alert handling workflow
- Distinguishing true positives from false positives
- Incident documentation and escalation
- Application of MITRE ATT&CK in real scenarios

---

## Skills & Technologies
- SIEM: **Splunk**
- Windows Security Logs
- **Sysmon**
- Alert triage & Incident Response (L1)
- MITRE ATT&CK
- SOC Operations
- Windows / Linux fundamentals

---

## Project Status
Work in progress – additional detections, dashboards, runbooks and screenshots are being added.


