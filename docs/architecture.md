# Lab Architecture

## Network Layout
- **Splunk Server (Ubuntu)**: 192.168.1.235  
- **Windows 10 Endpoint**: 192.168.1.110  
- **Attack Host (Kali Linux)**: 192.168.1.101  
- Network: 192.168.1.0/24 (VirtualBox)

## Components
- **Splunk SIEM** running on Ubuntu Server
- **Windows 10** endpoint with Security Event Logs and Sysmon enabled
- **Sysmon** configured to log process creation events (Event ID 1)
- Centralized log collection and analysis in Splunk

## Data Flow
1. Windows endpoint generates Security and Sysmon events  
2. Events are forwarded to Splunk SIEM  
3. SOC analysis is performed using Splunk searches and dashboards

## Purpose
This architecture supports detection and investigation of simulated security incidents from a SOC (L1) perspective, focusing on log analysis, alert triage and incident response.
