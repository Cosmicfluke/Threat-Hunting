//Kush + Claude
C2 Hunting — Rare & Suspicious Outbound Connections

Summary: (TLDR) This KQL query finds rare, newly-seen outbound connections to public internet hostnames.
It enriches missing hostnames, identifies the processes and devices involved, filters out noise, and highlights suspicious activity that may indicate command‑and‑control (C2) or malware callbacks.

This hunt helps analysts find unusual outbound connections from devices to the public internet.
These unusual connections can be early signs of:

* Malware calling home

* Command‑and‑control (C2) servers

* Suspicious scripts making network connections

* Compromised devices reaching out to attacker infrastructure

This README explains exactly what the KQL does, step‑by‑step, with code snippets and plain‑English explanations.

1st KQL snippet: Query Time Settings

set query_datetimescope_column = "Timestamp";
set query_datetimescope_to = datetime(2025-03-14T09:45:00);
set query_now = datetime(2025-03-14T09:45:00);

What this does
These lines set the time scope for the query.
They don’t change the logic — they simply tell Sentinel how to interpret timestamps.

Why this matters
It ensures the query runs consistently within a defined time window. Also, you can use this to change the scope to detect slow attacks. 

2nd KQL Snippet: Build a Hostname Lookup Table (Fix Missing Hostnames)

let IPHostLookup = 
    DeviceNetworkEvents
    | where Timestamp > ago(15d)
    | where isnotempty(RemoteUrl)
    | where RemoteIPType !in ("Private", "Loopback", "LinkLocal")
    | extend RemoteIP = replace_string(RemoteIP, "::ffff:", "")
    | where not(ipv4_is_private(RemoteIP))
    | extend HostName = replace_strings(RemoteUrl, dynamic(["https://", "http://"]), dynamic(["",""]))
    | extend HostName = replace_regex(HostName, @'\/.*', '')
    | extend HostName = replace_regex(HostName, @':\d+', '')
    | summarize by RemoteIP, HostName;
    
What this does
This section creates a table that maps:

Code
RemoteIP → HostName

It:

* Removes private/local IPs

* Cleans URLs

* Extracts hostnames

* Normalizes IPv6‑mapped IPv4 addresses

* Summarizes into one row per IP/hostname

Why this matters
Some network events only contain an IP address and no hostname.
This lookup table allows the query to fill in missing hostnames later, which is critical for identifying suspicious domains.

3rd Kql Snippet: Collect All Public Internet Connections

let InternetConnections = 
    DeviceNetworkEvents
    | where Timestamp > ago(15d)
    | where RemoteIPType !in ("Private", "Loopback", "LinkLocal")
    | extend RemoteIP = replace_string(RemoteIP, "::ffff:", "")
    | where not(ipv4_is_private(RemoteIP))
    | extend HostName = replace_strings(RemoteUrl, dynamic(["https://", "http://"]), dynamic(["",""]))
    | extend HostName = replace_regex(HostName, @'\/.*', '')
    | extend HostName = replace_regex(HostName, @':\d+', '')
    | project-reorder Timestamp, DeviceId, DeviceName, ActionType, RemoteIP, RemotePort, HostName, RemoteUrl;
    
What this does
This section collects all outbound connections to the public internet and cleans the hostnames.

Why this matters
This gives us a clean dataset of real internet activity, removing noise like:

* Internal traffic

* Loopback

* Private IP ranges

* Messy URLs

This is the foundation of the hunt.

4th KQL snippet: Join Internet Connections With Hostname Lookup

InternetConnections
| where ActionType in ("ConnectionSuccess", "ConnectionSuccessAggregatedReport")
| join kind=leftouter IPHostLookup on RemoteIP
| where HostName == HostName1 or isempty(HostName)
| extend HostName = coalesce(HostName, HostName1)
| where isnotempty(HostName)

What this does, this section:

* Keeps only successful connections

* Joins the lookup table

* Fills missing hostnames

* Removes duplicates

* Removes events where hostname is still empty

Why this matters
Attackers often use IP-only C2 servers.
This join ensures we capture as many hostnames as possible, even when Defender didn’t log them originally.

5Th KQL Snippet: Summarize Activity by Hostname

| summarize FirstSeen = arg_min(Timestamp, *),
            HostNameLocalPrevalence = dcount(DeviceId),
            ObservedDevices = make_set(DeviceName),
            SampleInitiatingProcessFolderPath = take_anyif(InitiatingProcessFolderPath, isnotempty(InitiatingProcessFolderPath)),
            SampleInitiatingProcessParentFileName = take_anyif(InitiatingProcessParentFileName, isnotempty(InitiatingProcessParentFileName)),
            ObservedProcesses = make_set_if(InitiatingProcessFileName, isnotempty(InitiatingProcessFileName)),
            ObservedInitiatingProcessFolderPaths = make_set_if(InitiatingProcessFolderPath, isnotempty(InitiatingProcessFolderPath))
            by HostName
            
What this does
For each hostname, the query collects:

* FirstSeen → When it first appeared

* HostNameLocalPrevalence → How many devices contacted it

* ObservedDevices → Which devices contacted it

* ObservedProcesses → Which processes contacted it

* SampleInitiatingProcessFolderPath → Where the process lived on disk

* SampleInitiatingProcessParentFileName → Parent process

* ObservedInitiatingProcessFolderPaths → All folder paths

Why this matters
This gives analysts a complete picture of how the hostname is being accessed.

Red flags include:

* Only one device contacting the hostname

* Processes running from AppData, Temp, or Downloads

* Script engines (powershell.exe, cmd.exe, wscript.exe)

* Suspicious parent-child chains

6th KQL Snippet: Filter for Rare & Suspicious Hostnames and final output

| where HostNameLocalPrevalence <= 2
| where FirstSeen >= ago(1d)
| where HostName !endswith ".office.com"
| where SampleInitiatingProcessFolderPath != "c:\\windows\\systemapps\\microsoft.windows.search_cw5n1h2txyewy\\searchapp.exe"
| project-reorder FirstSeen, HostName, SampleInitiatingProcessFolderPath, SampleInitiatingProcessParentFileName, ObservedProcesses, ObservedInitiatingProcessFolderPaths, ObservedDevices

What this does? 
This section keeps only:

* Hostnames contacted by 2 or fewer devices (you can chgnage it to your suitability) 

* Hostnames first seen within the last 24 hours

* Hostnames that are not Microsoft noise

* Processes that are not SearchApp.exe (very noisy)

This organizes the final results so analysts see: FirstSeen, HostName, SampleInitiatingProcessFolderPath, SampleInitiatingProcessParentFileName, ObservedProcesses, ObservedInitiatingProcessFolderPaths, ObservedDevices

* When the hostname first appeared

* Which hostname is suspicious

* Which process contacted it

* Where the process lived

* Which parent process spawned it

* All processes involved

* All devices involved

Why this matters
This removes normal enterprise traffic and highlights rare, new, unusual connections, the ones most likely to be malicious.

