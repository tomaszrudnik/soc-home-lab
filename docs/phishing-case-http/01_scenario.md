# Phishing Case – Fake Banking Portal (HTTP Simulation)

## Objective

Simulate a phishing scenario where a user clicks a malicious banking link.
Goal: analyze endpoint telemetry and determine impact from a SOC L1 perspective.

---

## Lab Environment

- SIEM: Splunk Enterprise
- Endpoint: Windows 10 (Security logs + Sysmon)
- Log Forwarding: Splunk Universal Forwarder
- Attack Simulation: Local HTTP server (Python)
- Network: 192.168.1.0/24 (VirtualBox lab)

---

## Scenario

User receives a phishing email with a link:

http://bank-secure-login.com/login

In lab:
- Fake page hosted locally
- User opens link in browser
- SOC investigates endpoint activity

---


# Investigation – Phishing Page Verification (SOC L1 Workflow)

## Objective

Verify whether the accessed web page is malicious using endpoint telemetry (Windows Security + Sysmon logs) in Splunk.

---

## Step 1 – Process Creation (User Action Confirmation)

### Query

```spl
index=windows EventCode=4688 earliest=-5m
NewProcessName="*chrome.exe"
| table _time host NewProcessName ParentProcessName
| sort -_time
```

### What to verify (Checklist)

- Confirm that the browser process was created
- Verify that `ParentProcessName = explorer.exe` (user-initiated execution)
- Confirm timestamp matches the click time

Conclusion: User action confirmed – browser launched after clicking the link.

---

## Step 2 – Command Line Inspection

### Query

```spl
index=windows EventCode=4688 earliest=-5m
NewProcessName="*chrome.exe"
| table _time host CommandLine ParentProcessName
| sort -_time
```

### What to verify (Checklist)

- Check if the URL appears in CommandLine
- Check for IP address instead of domain
- Check for non-standard port (e.g., 8080)
- Check if HTTP is used instead of HTTPS
- Confirm ParentProcessName = explorer.exe

Conclusion: Command-line parameters may reveal suspicious indicators even before network telemetry analysis.


