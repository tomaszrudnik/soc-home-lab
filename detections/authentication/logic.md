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

```
![Authentication volume: 4624 vs 4625](../../docs/screenshots/splunk/dashboard_authentication_4624_4625/panel_4624_vs_4625.png)



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

### Authentication Methods Observed (LogonType Mapping)

During the lab validation, different access methods produced different **LogonType** values:

- **LogonType 3 (Network)**  
  Typical for remote authentication over network protocols (e.g., SMB / WinRM).  
  Used to spot password guessing against exposed services.

- **LogonType 10 (RemoteInteractive)**  
  Typical for interactive remote logons (e.g., RDP).  
  Useful for detecting brute-force attempts targeting remote desktop access.

- **EventCode 4648 (Explicit credentials used)**  
  Indicates credentials were provided explicitly (credential reuse / “run as” style behavior).  
  Helpful for spotting lateral movement patterns when combined with 4624/4625.

  ---

### Detection A: Brute-force / password guessing (failed logons threshold)

This detection flags unusually high volumes of failed authentication attempts (**4625**) on a host.
It is a simple SOC L1 signal to prioritize triage.

```spl
index=windows sourcetype="XmlWinEventLog:Security" EventCode=4625
| stats count as failures by host
| where failures >= 10
| sort - failures
```
### Detection B: Success after multiple failures (4624 after 4625)

This detection identifies a **successful logon (4624)** that occurs shortly after
multiple **failed logons (4625)** for the same user on the same host.

It is useful for spotting cases where password guessing transitions into a valid login.

**Signal**
- `failed_count >= 5` within `5 minutes`
- `success_count >= 1` in the same time window
- grouped by `user + host`

```spl
index=windows sourcetype="XmlWinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| eval user=coalesce(user, Account_Name, TargetUserName)
| eval is_fail=if(EventCode=4625,1,0)
| eval is_success=if(EventCode=4624,1,0)
| bin _time span=5m
| stats
    sum(is_fail) as failed_count
    sum(is_success) as success_count
    values(LogonType) as logon_types
    values(IpAddress) as src_ip
    by _time, host, user
| where failed_count >= 5 AND success_count >= 1
| sort - _time
```





