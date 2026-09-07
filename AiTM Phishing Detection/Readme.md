# AiTM Phishing and Session Token Theft Detection

A configurable Kusto Query Language (KQL) threat-hunting query for detecting potential adversary-in-the-middle (AiTM) phishing, session-cookie theft, and session-token replay activity in Microsoft Entra ID sign-in telemetry.

## Requirements

**Supported platforms**

- Microsoft Sentinel
- Azure Monitor Log Analytics

**Required data connector**

- Microsoft Entra ID

**Required tables**

- `SigninLogs` — interactive Microsoft Entra user sign-ins
- `AADNonInteractiveUserSignInLogs` — non-interactive Microsoft Entra user sign-ins

This query is written for the Microsoft Sentinel / Log Analytics schema. It is not directly compatible with Microsoft Defender XDR Advanced Hunting, which uses different Entra sign-in tables and field names. 

## Overview

AiTM phishing places a reverse proxy between a victim and a legitimate sign-in page. The attacker can capture credentials, complete or relay multifactor authentication, steal the authenticated session cookie, and replay the victim's session.

This hunt identifies successful interactive Microsoft Entra sign-ins that combine several suspicious signals:

- A source IP address not seen during the configured baseline period.
- A source IP first observed during the recent detection period.
- A new `SessionId`.
- No Microsoft Entra `DeviceId` recorded in `DeviceDetail`.
- Access to one or more configured monitored applications.
- Optional enrichment where the same session appears from more than one IP address.
- Microsoft Entra risk signals, when available.

The query is a hunting analytic. It produces leads for investigation and does not independently confirm AiTM phishing or account compromise.

## Data Sources

The query requires:

| Table | Purpose |
|---|---|
| `SigninLogs` | Interactive Microsoft Entra user sign-in events |
| `AADNonInteractiveUserSignInLogs` | Non-interactive sign-in events used to validate session history |

Important fields include:

- `TimeGenerated`
- `CreatedDateTime`
- `UserPrincipalName`
- `IPAddress`
- `AppId`
- `AppDisplayName`
- `SessionId`
- `UniqueTokenIdentifier`
- `CorrelationId`
- `DeviceDetail`
- `ResultType`
- `RiskLevelDuringSignIn`
- `RiskState`
- `RiskEventTypes_V2`
- `ConditionalAccessStatus`

Run the following before using the query in a new environment:

```kql
SigninLogs
| getschema
```

```kql
AADNonInteractiveUserSignInLogs
| getschema
```

## Configuration

Edit the configuration block at the top of the KQL file.

| Setting | Default | Purpose |
|---|---:|---|
| `LookbackPeriod` | `14d` | Entire period used to establish normal IP and session history |
| `RecentPeriod` | `1d` | Most recent period where new activity is evaluated |
| `MinimumRiskScore` | `3` | Minimum score needed for a result |
| `MonitoredAppIds` | Microsoft portal-related app IDs | Applications that should increase prioritization |
| `RequireMonitoredApplication` | `true` | Restricts results to configured applications |
| `ExcludedUsers` | Empty | Add approved test, service, or automation identities |
| `ExcludedIPs` | Empty | Add trusted corporate egress, proxy, or test IP addresses |

### Add monitored applications

Add an application/client ID to `MonitoredAppIds`:

```kql
let MonitoredAppIds = dynamic([
    "4765445b-32c6-49b0-83e6-1d93765276ca",
    "YOUR-APPLICATION-CLIENT-ID-HERE"
]);
```

Set the following to `false` to evaluate successful sign-ins to all applications:

```kql
let RequireMonitoredApplication = false;
```

### Use historical or lab data

The query runs against live data by default. Do not use the fixed-date settings in production.

For historical datasets or lab exercises, uncomment and edit:

```kql
set query_datetimescope_column = "TimeGenerated";
set query_datetimescope_to = datetime(2026-04-26T23:59:59);
set query_now = datetime(2026-04-26T23:59:59);
```

## Detection Logic

The query performs these steps:

1. Retrieves successful interactive sign-ins for the full lookback period.
2. Extracts device fields from the `DeviceDetail` JSON object.
3. Creates a baseline of IP addresses seen before the recent detection period.
4. Creates a baseline of session IDs observed in interactive sign-ins.
5. Creates a baseline of session IDs observed in non-interactive sign-ins.
6. Identifies recent successful sign-ins from IPs absent from the prior baseline.
7. Requires a nonempty `SessionId` not observed during the baseline.
8. Requires a missing Entra `DeviceId`.
9. Optionally requires the sign-in to target a monitored application.
10. Enriches results with session-to-IP counts and Entra risk information.
11. Assigns a risk score and returns results at or above the configured threshold.

## Risk Scoring

| Signal | Score |
|---|---:|
| New IP address | +1 |
| New session ID | +1 |
| Missing Entra Device ID | +1 |
| Access to a configured monitored application | +1 |
| Same session observed from multiple IP addresses | +1 |
| Entra risk signal present | +1 |

The default threshold is:

```kql
let MinimumRiskScore = 3;
```

Increase the threshold to reduce results. Decrease it to broaden hunting coverage.

## Result Interpretation

A result indicates a successful sign-in that meets the configured detection criteria.

Important output fields:

| Field | Investigation value |
|---|---|
| `UserPrincipalName` | Potentially affected identity |
| `IPAddress` | Source address to validate, enrich, and search across logs |
| `SessionId` | Pivot for session reuse, token replay, and downstream activity |
| `UniqueTokenIdentifier` | Pivot for token-related activity |
| `CorrelationId` | Link related authentication activity |
| `DeviceId` | Missing value may indicate an unregistered or unknown device |
| `SessionIPCount` | Values above one can indicate session reuse across IPs |
| `RiskEventTypes_V2` | Microsoft Entra risk detections, if present |
| `ConditionalAccessStatus` | Determines whether policy controls applied |
| `AppDisplayName` | Indicates the application accessed |

## Investigation Workflow

For every high-confidence result:

1. Confirm whether the user recognizes the sign-in time, IP address, country, device, browser, and application.
2. Investigate the source IP using approved reputation, ASN, proxy, VPN, and geolocation tooling.
3. Review all `SigninLogs` events for the same `UserPrincipalName`, `IPAddress`, `SessionId`, and `UniqueTokenIdentifier`.
4. Determine whether the same `SessionId` appears from multiple IP addresses, locations, browsers, or devices.
5. Review `RiskLevelDuringSignIn`, `RiskState`, `RiskDetail`, and `RiskEventTypes_V2`.
6. Review Conditional Access outcomes and MFA authentication details.
7. Search Microsoft 365 audit logs for mailbox rule creation, forwarding changes, delegated access, suspicious OAuth consent, SharePoint access, Teams access, or unusual downloads following the sign-in.
8. Search mail telemetry for phishing messages, credential-harvesting URLs, and user interaction before the suspicious sign-in.
9. Compare activity against approved corporate VPNs, proxies, virtual desktops, travel, managed devices, and IT automation.

## Response Guidance

If compromise is confirmed or strongly suspected:

1. Revoke the user's active sessions.
2. Reset the password and review the account's registered authentication methods.
3. Investigate and remove malicious inbox rules, forwarding settings, OAuth grants, and unauthorized delegation.
4. Block confirmed malicious infrastructure according to organizational process.
5. Search for the same infrastructure, token identifiers, and session patterns across other users.
6. Preserve relevant logs, timestamps, IPs, correlation IDs, and token identifiers for incident response.

Follow your organization's incident-response procedures before taking containment actions.

## Tuning Guidance

Expected false positives can include:

- Corporate VPN egress addresses.
- Secure web gateways and enterprise proxies.
- Virtual desktop infrastructure.
- Mobile networks.
- Home network IP changes.
- Bring-your-own-device access.
- Browser privacy features.
- Users traveling between locations.
- Application behavior that produces new session IDs.
- Legitimate unmanaged-device access.

Tune by adding known-good identities to `ExcludedUsers` and trusted egress IPs to `ExcludedIPs`.

Do not treat a missing device ID, a public IP, a new session, or a new IP address as proof of compromise in isolation.

## Limitations

- AiTM phishing can use legitimate or residential proxy infrastructure.
- Not every AiTM attack creates an Entra risk detection.
- Not every stolen session produces a visible multi-IP session pattern.
- A new IP or session can be legitimate.
- Device IDs can be missing for legitimate unmanaged, mobile, browser, virtual desktop, and privacy-focused access.
- Non-interactive sign-in data may not be available in every workspace.
- Field availability differs between tenants, data connectors, and schema versions.
- This query detects suspicious sign-in patterns, not the phishing email or phishing website itself.

## MITRE ATT&CK Context

This hunt can support investigation of:

- T1566 — Phishing
- T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning and related AiTM concepts
- T1539 — Steal Web Session Cookie
- T1550.004 — Use Alternate Authentication Material: Web Session Cookie
- T1078 — Valid Accounts

Validate any technique mapping against the actual observed evidence.

## License and Disclaimer

Use this query only in environments where you are authorized to monitor and investigate identity activity. Test and tune it against known benign activity before creating an alert, automated response, or production detection rule.
