# Detection: Authentication Abuse (4624/4625)

## Description
This detection focuses on identifying suspicious authentication activity on Windows endpoints using Windows Security logs:
- **4625** (Failed logon)
- **4624** (Successful logon)
- **4648** (Explicit credentials used)

It is designed for **SOC L1 triage** to spot password-guessing patterns and confirm when an attacker transitions from repeated failures to a successful authentication.

---

## Data Sources

### Windows Security
- Log source: Security
- Sourcetype: `XmlWinEventLog:Security`
- EventCodes: `4624`, `4625`, `4648`

---

## Detection Logic (SOC L1)

### Baseline: Volume of 4624/4625
Validates ingestion and provides quick visibility into success vs failure counts.

```spl
index=windows sourcetype="XmlWinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| stats count by EventCode
| sort - count



## Attack Simulation (Lab Context)

To validate this detection, a controlled authentication abuse scenario was simulated
in a local SOC home lab environment.

The purpose of the simulation was **not exploitation**, but to intentionally generate
realistic Windows authentication telemetry that SOC analysts commonly investigate
in production environments.

The simulation focused on:
- repeated failed authentication attempts (EventCode 4625)
- transition from failed to successful authentication (EventCode 4624)
- different Windows logon types depending on access method

All activity was executed against a **test Windows host** with full authorization,
strictly for defensive detection validation.
