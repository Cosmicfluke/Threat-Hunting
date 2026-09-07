# Scheduled Task Abuse + C2 Detection (KQL Hunt)

This hunt detects suspicious use of `schtasks.exe` for persistence and correlates
task creation with outbound network activity to identify potential command‑and‑control (C2).

## What this hunt identifies

- Non‑SYSTEM scheduled task creation (`AccountSid != S-1-5-18`) 
- Suspicious parent processes (PowerShell, Office apps, browsers, LOLBins)
- Suspicious paths (AppData, Temp, ProgramData, Public, Downloads)
- Suspicious command patterns (certutil, bitsadmin, curl, wget, base64, etc.)
- Outbound network activity within 1 hour of task creation
- Suspicious network indicators:
  - DNS‑over‑HTTPS (`/dns-query`)
  - High ports (>10000)
  - Ports 8080 / 8443
  - Suspicious TLDs (`.xyz`, `.top`)

A scoring system combines these signals to surface high‑confidence malicious
scheduled task abuse.

## File

`scheduled_task_abuse_c2_detection_v7.kql`

## MITRE ATT&CK

- T1053.005 — Scheduled Task
- T1059 — Command and Scripting Interpreter
- T1105 — Ingress Tool Transfer
- T1071.004 — DNS over HTTPS
- T1071.001 — Web Protocols
- T1547 — Persistence
- T1021 — Remote Services
