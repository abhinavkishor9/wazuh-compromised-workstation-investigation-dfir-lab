# Investigation Notes

## Lab Summary

This investigation reconstructed a controlled multi-stage workstation compromise scenario on `DESKTOP-9MMM37V`.

The laboratory sequence included creation of a controlled user account, endpoint discovery, PowerShell payload execution, scheduled-task persistence, local network staging, and a Microsoft Defender configuration change.

Windows Security, Sysmon, Task Scheduler, Microsoft Defender, and Wazuh were used to examine the activity.

The investigation also identified several evidence limitations, including machine-account authentication events and unrelated background network telemetry.

---

## Analyst Methodology

1. Establish endpoint and Wazuh baseline.
2. Record current user and host context.
3. Create controlled investigation workspace.
4. Capture Defender baseline.
5. Create controlled test account.
6. Enable required authentication auditing.
7. Generate harmless PowerShell activity.
8. Establish scheduled-task persistence.
9. Preserve the task configuration.
10. Stage controlled network activity.
11. Review Windows authentication telemetry.
12. Review PowerShell and process telemetry.
13. Review Task Scheduler activity.
14. Review Defender configuration change telemetry.
15. Correlate evidence in Wazuh.
16. Separate relevant events from unrelated activity.
17. Assess the complete incident chain.
18. Document evidence limitations.

---

## Investigation Scenario

A Windows workstation exhibits a sequence of security-relevant activities that may indicate compromise.

The analyst needs to determine whether the events represent:

- A genuine attack chain
- Authorized administration
- Background Windows activity
- Controlled testing

The investigation therefore focuses on linking activity across authentication, execution, persistence, network, and security-control evidence.

---

## Evidence Collected

### Evidence 1 – Wazuh Endpoint

Collected:

- Agent ID: `001`
- Agent Name: `DESKTOP-9MMM37V`
- Status: `Active`
- OS: Windows 11 Pro
- Wazuh Version: `4.12.0`

Finding:

The endpoint was actively reporting to Wazuh.

---

### Evidence 2 – Endpoint Identity

Commands:

```powershell
hostname
```

```powershell
whoami
```

```powershell
whoami /user
```

Observed:

```text
Hostname: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
```

Finding:

Established the workstation and active user context.

---

### Evidence 3 – Investigation Workspace

Created:

```text
C:\CompromisedWorkstationLab
```

Observed creation time:

```text
18-08-2026 09:48
```

Finding:

Established the controlled staging location for the laboratory activity.

---

### Evidence 4 – Defender Baseline

Command:

```powershell
Get-MpComputerStatus
```

Observed baseline:

```text
AMServiceEnabled           : True
AntivirusEnabled           : True
RealTimeProtectionEnabled  : False
BehaviorMonitorEnabled     : False
IoavProtectionEnabled      : False
```

Finding:

Several Defender protection features were already disabled before the simulated configuration change.

This is important pre-existing state and should not be attributed to the later lab actions.

---

### Evidence 5 – Controlled Account Creation

Command:

```cmd
net user CompromiseTest Password123! /add
```

Finding:

A controlled local test account was created.

The account was not used as evidence of a confirmed compromise.

---

### Evidence 6 – Authentication Audit Configuration

Initial configuration:

```text
Logon: No Auditing
```

The lab then enabled successful and failed logon auditing.

Finding:

Authentication visibility was intentionally improved for the laboratory.

---

### Evidence 7 – Authentication Telemetry

Observed:

```text
Event ID 4624
Event ID 4625
```

The captured events showed:

```text
Account Name: DESKTOP-9MMM37V$
Security ID: SYSTEM
Account Domain: WORKGROUP
```

Finding:

These events represent machine-account/system authentication.

They do not prove that `CompromiseTest` logged in.

---

### Evidence 8 – PowerShell Payload

Created:

```text
C:\CompromisedWorkstationLab\payload.ps1
```

The payload recorded:

- Timestamp
- Hostname
- User

Execution output confirmed:

```text
Host: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
```

Finding:

PowerShell payload execution was successfully validated.

---

### Evidence 9 – PowerShell Execution

Command:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\CompromisedWorkstationLab\payload.ps1
```

Finding:

PowerShell execution with `ExecutionPolicy Bypass` was observed as controlled laboratory activity.

---

### Evidence 10 – Scheduled-Task Persistence

Task:

```text
CompromisedLab-Persistence
```

Action:

```text
powershell.exe
```

Arguments:

```text
-NoProfile -File C:\CompromisedWorkstationLab\payload.ps1
```

Trigger:

```text
AtLogOn
```

Finding:

A controlled persistence mechanism was successfully registered.

---

### Evidence 11 – Task Definition

Preserved:

```text
C:\CompromisedWorkstationLab\task-definition.xml
```

Finding:

The persistence configuration was preserved for forensic reconstruction.

---

### Evidence 12 – Controlled Network Listener

Created:

```text
127.0.0.1:9091
```

Finding:

A local listener was staged for controlled network telemetry generation.

No external C2 destination was used.

---

### Evidence 13 – Sysmon Event ID 1

Observed:

```text
Image:
C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe

Process creation:
18-08-2026 10:32:15
```

Finding:

PowerShell process creation telemetry was available for the controlled activity.

---

### Evidence 14 – Sysmon Event ID 3

Observed:

```text
Image:
C:\Users\Dell\AppData\Local\Programs\Zoho Mail - Desktop\Zoho Mail - Desktop.exe

User:
DESKTOP-9MMM37V\Dell

Protocol:
tcp

Initiated:
true
```

Finding:

This was valid network telemetry, but it represented Zoho Mail Desktop background traffic rather than the controlled `127.0.0.1:9091` test.

The event was therefore excluded from the simulated compromise chain.

---

### Evidence 15 – Defender Event ID 5007

Observed:

```text
Event ID: 5007
Logged: 18-08-2026 10:32:19
```

Change:

```text
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\CompromisedWorkstationLab
```

Finding:

Confirmed that the investigation directory was added as a Defender exclusion.

---

### Evidence 16 – Wazuh Correlation

Wazuh searches included:

```text
agent.name: DESKTOP-9MMM37V
```

```text
CompromiseTest
```

```text
powershell.exe
```

```text
CompromisedLab-Persistence
```

```text
5007
```

Finding:

Wazuh provided centralized visibility for endpoint investigation and correlation.

---

## Evidence Correlation

| Evidence | Observation | Interpretation |
|---|---|---|
| Wazuh Agent | Active | Endpoint reporting confirmed |
| Workspace | Lab directory created | Controlled staging |
| Test User | `CompromiseTest` | Simulated account activity |
| Defender Baseline | Protections already disabled | Pre-existing state |
| PowerShell | Script executed | Controlled execution |
| ExecutionPolicy | Bypass used | Suspicious-looking indicator |
| Scheduled Task | Persistence created | Controlled persistence |
| Sysmon 1 | PowerShell process | Execution telemetry |
| Defender 5007 | Exclusion added | Security configuration change |
| 4624/4625 | Machine account | Not proof of CompromiseTest logon |
| Sysmon 3 | Zoho Mail | Unrelated network activity |
| Wazuh | Endpoint telemetry | Centralized correlation |

---

## DFIR Analysis

The evidence demonstrates a multi-stage sequence that resembles a workstation compromise:

```text
Account Creation
      ↓
PowerShell Execution
      ↓
Scheduled Task
      ↓
Defender Exclusion
      ↓
Network Staging
```

However, individual evidence sources must be interpreted carefully.

The Defender exclusion is directly supported by Event ID 5007. PowerShell execution is supported by Sysmon Event ID 1 and direct execution evidence. Scheduled-task persistence is supported by the task configuration.

The authentication screenshots, however, show machine-account events rather than `CompromiseTest`. Likewise, the displayed Sysmon Event ID 3 belongs to Zoho Mail Desktop.

Therefore, the evidence supports the existence of the controlled activity chain, but it does not independently demonstrate a genuine external compromise.

---

## Analyst Observations

- Wazuh was active throughout the investigation.
- The workstation was `DESKTOP-9MMM37V`.
- The active user was `desktop-9mmm37v\dell`.
- Defender already had several disabled protection layers before the lab changes.
- The test account was created for controlled simulation.
- PowerShell execution was successfully demonstrated.
- Scheduled-task persistence was successfully created.
- The task definition was preserved.
- Defender Event ID 5007 confirmed the exclusion change.
- Sysmon Event ID 1 provided PowerShell process telemetry.
- The displayed Sysmon Event ID 3 was unrelated background traffic.
- The displayed authentication events were for the machine account.
- Some expected correlation evidence was therefore unavailable or unrelated.

---

## Investigation Assessment

The evidence supports:

- Controlled PowerShell execution
- Controlled persistence creation
- Controlled Defender configuration modification
- Endpoint telemetry visibility

The evidence does not establish:

- Real attacker access
- A confirmed CompromiseTest logon
- External C2 activity
- Malicious intent
- That pre-existing disabled Defender protections were caused by the laboratory

Final assessment:

**Controlled compromised-workstation simulation with multiple correlated security-relevant behaviors and documented evidence limitations.**

---

## Conclusion

The investigation demonstrated how a workstation compromise can be reconstructed through multiple evidence layers rather than a single alert.

The strongest evidence came from PowerShell execution, scheduled-task persistence, Defender Event ID 5007, Sysmon process telemetry, and Wazuh endpoint visibility.

The lab also demonstrated the importance of evidence attribution. Machine-account logons and unrelated Zoho Mail network activity were excluded rather than incorrectly incorporated into the compromise narrative.
