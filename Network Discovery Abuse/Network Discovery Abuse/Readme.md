1. Hypothesis
_______________

If a user or process runs multiple built‑in Windows network discovery commands within a short period, it may indicate attacker reconnaissance or scripted enumeration. This exists because these are some of the tools I would use once I have a shell on a machine. 

This hunt is designed to detect:

Privilege escalation reconnaissance

Lateral movement preparation

Script‑based discovery (PowerShell, batch files, etc.)

Post‑exploitation enumeration

Suspicious use of built‑in utilities

2. How the Hunt Works (Step‑by‑Step Breakdown)
______________________________________________

Below is the full breakdown of the KQL query, with code snippets and clear explanations.

Step 1 — Look for Network Discovery Commands
kql
DeviceProcessEvents
| where Timestamp > ago(15d)
| where FileName in~ ("ipconfig.exe", "netstat.exe", "nslookup.exe", "ping.exe", "arp.exe")
What this does
This section looks for any execution of the five built‑in Windows tools commonly used for network discovery.

Why this matters
Attackers frequently run these commands to:

* View network configuration (ipconfig)

* Inspect active connections (netstat)

* Resolve hostnames (nslookup)

* Test reachability (ping)

* View ARP cache (arp -a)

Running all of them together is highly suspicious.

Step 2 — Group Commands by Process

| summarize commands = make_set(FileName)
  by InitiatingProcessUniqueId, InitiatingProcessFileName, DeviceName
| where array_length(commands) > 3

What this does
This groups all discovery commands executed by the same initiating process and checks if more than three different commands were used.

Why this matters
Running one command is normal.

Running four or more is unusual and often indicates:

* Recon scripts

* Attacker toolkits

* Batch files

* PowerShell enumeration

This is where suspicious behavior begins to stand out.

Step 3 — Add Context About the Process

| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(15d)
    | summarize arg_max(Timestamp, *) by InitiatingProcessUniqueId, DeviceId
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
              InitiatingProcessIntegrityLevel, InitiatingProcessAccountName,
              LogonId, InitiatingProcessLogonId, InitiatingProcessUniqueId,
              InitiatingProcessParentFileName
)
on DeviceName, InitiatingProcessFileName, InitiatingProcessUniqueId

What this does
This adds context about the process that executed the commands:

Who ran it

* What parent process spawned it

* Integrity level (admin or user)

* Logon session

* Device name

Why this matters
Context helps hunters determine whether the behavior is legitimate or suspicious.

Examples:

powershell.exe spawning ipconfig.exe → suspicious

cmd.exe spawning all commands → suspicious

explorer.exe spawning them → extremely suspicious

Step 4 — Add Identity Information

| join kind=leftouter (
    IdentityInfo
    | where Timestamp > ago(15d)
    | summarize arg_max(Timestamp, *) by AccountUpn
    | project AccountUpn, AccountName, Department, JobTitle
)
on AccountName

What this does
This adds user identity details:

* Username

* Department

Job title

Why this matters
This helps analysts answer:

* Is this an IT admin?

* Is this a developer?

* Is this a normal user who should NOT be running discovery commands? //Why the hell is the sales assistant running ipconfig/showall 

Identity context is crucial for triage.

TLDR What This Hunt Produces (for novice hunter's -> Output)

This hunt gives you a list of:

* Devices running multiple discovery commands

* Users who executed them

* Processes responsible

* Parent processes

* Integrity levels

* Whether the behavior is new or unusual

Red Flags to Look For:

* powershell.exe running all commands

* cmd.exe running them in sequence

* wscript.exe or cscript.exe spawning them

* Discovery commands run by non‑IT users

* Discovery commands run outside business hours

* Discovery commands run on servers

* Discovery commands run by service accounts

* These are strong indicators of attacker reconnaissance.
