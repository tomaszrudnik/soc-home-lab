
🔗 **Download CV (PDF):**  
[Tomasz_Samel_Junior_SOC_Analyst.pdf](./Tomasz_Samel_Junior_SOC_Analyst.pdf)

---


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


## How I Approach Alerts and Incidents (SOC L1 Perspective)

This lab reflects how a **SOC L1 analyst evaluates alerts and decides when an incident may be occurring**.

### Alert Interpretation
Each alert is treated as a **signal**, not an incident by default.
I first determine:
- what behavior triggered the alert
- whether the activity is expected or unusual
- how frequently it occurs and in what context

Simple, explainable detections are preferred to reduce false positives.

### Triage and Context Building
Before escalation, basic context is established:
- affected host and user
- sequence of related events (e.g. failures followed by success)
- type of access or activity observed
- whether the behavior is isolated or recurring

This helps distinguish normal activity from suspicious patterns.

### Escalation Logic
An alert is escalated to a potential incident when:
- repeated failures occur in a short time window
- suspicious activity transitions to success
- elevated privileges or sensitive access methods are involved
- activity aligns with known attack patterns (e.g. brute-force, misuse of valid accounts)

Focus is placed on **impact and prioritization**, not alert volume.

### Continuous Improvement
Detections are reviewed and adjusted based on:
- observed false positives
- behavioral changes over time
- lessons learned during lab validation

This mirrors real SOC workflows, where detections evolve continuously.

---



## Simulated Incident (High-Level)
A controlled attack scenario is executed in the lab to simulate a compromised Windows endpoint.
The focus of this project is **not exploitation**, but **detection, investigation and response** from a SOC perspective.
All attack activity was manually executed in a controlled lab environment
to generate authentic Windows telemetry for defensive detection validation.

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


