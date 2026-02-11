# Phishing Case – Fake Banking Portal (HTTP Simulation)

## Objective

Simulate a phishing scenario where a user clicks a malicious banking link.  
Goal: analyze endpoint telemetry and determine impact from a SOC L1 perspective.

---

## Lab Environment

- SIEM: Splunk Enterprise  
- Endpoint: Windows 10 (Security logs + Sysmon)  
- Log Forwarding: Splunk Universal Forwarder  
- Attack Simulation: Local HTTP server (Ubuntu – python3 http.server 8080)  
- Network: 192.168.1.0/24 (VirtualBox lab)  

---

# Investigation – Phishing Page Verification (SOC L1 Workflow)

---

## Step 1 – Process Creation (Browser Launch Confirmation)

### Query (confirmed working in lab)

```spl
index=windows EventCode=4688 earliest=-30m
"*chrome.exe"
| table _time host _raw
| sort -_time
```

### What was verified

- Event ID 4688 observed
- `_raw` contains `chrome.exe`
- Process path: C:\Program Files\Google\Chrome\Application\chrome.exe
- ParentProcessName visible inside raw event
- Timestamp matches user click

**Conclusion:**  
User manually launched Chrome after clicking the link.

---

## Step 2 – Command Line Inspection

### Query (confirmed working in lab)

```spl
index=windows EventCode=4688 earliest=-30m
"*chrome.exe" "CommandLine"
| table _time host _raw
| sort -_time
```

### What was verified inside `_raw`

- CommandLine field present
- Reference to accessed URL/IP
- Usage of HTTP (no HTTPS)
- Potential presence of port 8080
- ParentProcessName value

**Conclusion:**  
Process creation logs confirm how the browser was started and allow inspection of execution parameters.

---

## Step 3 – Network Connection Confirmation (Sysmon Event ID 3)

### Query (confirmed working in lab)

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-30m
"*chrome.exe*" AND ("192.168.1.235" OR "8080")
| table _time host _raw
| sort -_time
```

### What was verified inside `_raw`

- Event ID 3 (Network Connection)
- Image = chrome.exe
- DestinationIp = 192.168.1.235
- DestinationPort = 8080
- TCP connection initiated

**Conclusion:**  
Chrome established a direct HTTP connection to the phishing server hosted at 192.168.1.235:8080.

---

## Step 4 – Post-Click Execution Check

### Query (confirmed working in lab)

```spl
index=windows EventCode=4688 earliest=-30m
("cmd.exe" OR "powershell.exe" OR "mshta.exe" OR "wscript.exe" OR "rundll32.exe" OR "certutil.exe")
"chrome.exe"
| table _time host _raw
| sort -_time
```

### What was verified

- Multiple chrome.exe processes (normal browser behavior)
- No evidence of:
  - powershell.exe
  - cmd.exe
  - mshta.exe
  - wscript.exe
  - rundll32.exe
- No suspicious child process execution detected

**Conclusion:**  
No post-click payload execution observed. Activity limited to browser execution only.

---

# Final SOC L1 Assessment

### Findings

- Browser launch confirmed (Event ID 4688)
- Network connection confirmed (Sysmon Event ID 3)
- Direct IP usage (192.168.1.235)
- Non-standard port (8080)
- HTTP protocol (unencrypted)
- No evidence of further exploitation

### Incident Classification

Phishing exposure without confirmed endpoint compromise.

### Recommended Actions

- Reset user credentials
- Monitor authentication logs
- Conduct user awareness training
- Continue monitoring for abnormal outbound connections
