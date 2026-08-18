# Compromised Workstation Investigation with Wazuh (DFIR Lab 54)

## Overview

A compromised workstation investigation requires analysts to correlate multiple stages of endpoint activity rather than treating individual alerts as isolated incidents.

In this controlled DFIR lab, a sequence of benign activities was generated to simulate a possible workstation compromise. The activity included endpoint discovery, creation of a controlled test account, PowerShell payload execution, scheduled-task persistence, network listener staging, and a Microsoft Defender exclusion.

Windows Security logs, Task Scheduler telemetry, Sysmon process telemetry, Microsoft Defender Event ID 5007, and Wazuh endpoint visibility were used to reconstruct the activity.

The investigation also emphasizes evidence validation. Some events observed during the lab were unrelated background activity, so they were not incorrectly attributed to the simulated compromise chain.

---

# Lab Objectives

- Reconstruct a multi-stage endpoint activity sequence.
- Correlate authentication, execution, persistence, network, and security-tool telemetry.
- Identify the processes and users associated with the simulated activity.
- Investigate PowerShell execution and process creation.
- Investigate scheduled-task persistence.
- Investigate Microsoft Defender configuration changes.
- Investigate network activity generated during the lab.
- Correlate endpoint evidence with Wazuh.
- Distinguish directly observed evidence from unrelated telemetry.
- Identify evidence gaps and avoid unsupported compromise claims.
- Build an incident timeline from multiple independent artifacts.

---

# Lab Environment

| Component          | Value                                      |
| ------------------ | ------------------------------------------ |
| Host OS            | Windows 11 Pro                             |
| SIEM               | Wazuh 4.12                                 |
| Endpoint Agent     | Wazuh Agent                                |
| Endpoint Name      | DESKTOP-9MMM37V                            |
| Agent ID           | 001                                        |
| Test Account       | CompromiseTest                             |
| Investigation Type | Controlled Compromised Workstation Lab     |
| Lab Directory      | C:\CompromisedWorkstationLab               |
| Persistence        | CompromisedLab-Persistence                 |
| Test Port          | 9091                                       |
| Primary Telemetry  | Security / Sysmon / Defender / Wazuh       |

---

# Tools Used

- PowerShell
- Command Prompt
- `auditpol`
- `whoami`
- `hostname`
- Microsoft Defender
- `Get-MpComputerStatus`
- `Add-MpPreference`
- `Get-MpPreference`
- Scheduled Tasks
- `Register-ScheduledTask`
- `Get-ScheduledTask`
- `Get-ScheduledTaskInfo`
- Windows Security Event ID 4624
- Windows Security Event ID 4625
- Windows Security Event ID 4688
- Task Scheduler Operational logs
- Sysmon Event ID 1
- Sysmon Event ID 3
- Wazuh Discover

---

# Investigation Scenario

A Windows workstation is being investigated after a sequence of activities suggests possible compromise.

The analyst observes a combination of:

- New account activity
- PowerShell execution
- Scheduled-task persistence
- Defender configuration changes
- Network activity
- Process creation events

The investigation must determine whether these events form a meaningful compromise chain or whether some observations are unrelated background activity.

The key investigative question is:

> Does the combined endpoint evidence support a compromised-workstation hypothesis?

---

# Investigation Workflow

```text
Endpoint Baseline
       ↓
User / Account Activity
       ↓
PowerShell Execution
       ↓
Persistence
       ↓
Network Activity
       ↓
Defender Configuration Change
       ↓
Windows + Sysmon Telemetry
       ↓
Wazuh Correlation
       ↓
Evidence Validation
       ↓
Timeline Reconstruction
       ↓
Incident Assessment
```

---

# Investigation Steps

## Step 1 – Verify the Wazuh Agent

The Wazuh manager was checked using:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Observed:

- Agent ID: `001`
- Agent Name: `DESKTOP-9MMM37V`
- Status: `Active`
- OS: Microsoft Windows 11 Pro
- Wazuh Version: `4.12.0`

Wazuh Syscheck activity had also been recorded earlier, providing an endpoint baseline before the lab modifications.

---

## Step 2 – Identify the Endpoint and User

Commands used:

```powershell
hostname
```

```powershell
whoami
```

```powershell
whoami /user
```

Observed endpoint:

```text
DESKTOP-9MMM37V
```

Observed user:

```text
desktop-9mmm37v\dell
```

A local user SID was also recorded during the baseline stage.

---

## Step 3 – Create the Investigation Workspace

```powershell
New-Item -Path "C:\CompromisedWorkstationLab" -ItemType Directory -Force
```

The workspace was created at approximately:

```text
18-08-2026 09:48
```

The directory became the controlled staging area for the lab.

---

## Step 4 – Establish Defender Baseline

The endpoint's Defender state was collected using:

```powershell
Get-MpComputerStatus
```

The baseline showed:

- Antivirus service enabled
- Antivirus enabled
- Real-Time Protection: `False`
- Behavior Monitor: `False`
- IOAV Protection: `False`

The baseline was saved to:

```text
C:\CompromisedWorkstationLab\defender-baseline.txt
```

Important observation:

These protection states were already `False` during baseline collection. They should therefore **not** be attributed to the later simulated compromise activity.

---

## Step 5 – Create Controlled Test Account

A local account was created:

```cmd
net user CompromiseTest Password123! /add
```

The account was created for controlled investigation purposes.

It was not added to the local Administrators group.

---

## Step 6 – Review Authentication Auditing

The logon audit configuration was checked using:

```cmd
auditpol /get /subcategory:"Logon"
```

The policy was initially shown as:

```text
No Auditing
```

Logon auditing was then enabled for the laboratory scenario:

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

This allowed authentication telemetry to be investigated during the later stages.

---

## Step 7 – Review Authentication Events

Security Event ID 4624 and Event ID 4625 were reviewed.

Observed events included:

```text
4624 – Successful Logon
4625 – Failed Logon
```

However, the captured events shown in the evidence identified:

```text
Account Name: DESKTOP-9MMM37V$
Security ID: SYSTEM
Account Domain: WORKGROUP
```

These are machine-account/system authentication events.

Therefore, the screenshots do not independently prove that `CompromiseTest` successfully authenticated.

This is recorded as an evidence limitation rather than being treated as proof of compromise.

---

## Step 8 – Create the Harmless PowerShell Payload

The following payload was written to:

```text
C:\CompromisedWorkstationLab\payload.ps1
```

The payload recorded:

- Execution timestamp
- Hostname
- Current user

The payload was successfully executed and produced:

```text
C:\CompromisedWorkstationLab\execution.txt
```

The output identified:

```text
Host: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
```

---

## Step 9 – Execute the Payload Through PowerShell

The script was executed using:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\CompromisedWorkstationLab\payload.ps1
```

The use of `ExecutionPolicy Bypass` created an additional investigative indicator.

The execution itself remained harmless because the payload only recorded host and user information.

---

## Step 10 – Establish Scheduled-Task Persistence

A controlled scheduled task named:

```text
CompromisedLab-Persistence
```

was registered.

The task action was:

```text
powershell.exe
```

with:

```text
-NoProfile -File C:\CompromisedWorkstationLab\payload.ps1
```

The trigger was:

```text
AtLogOn
```

The task was successfully created and entered the `Ready` state.

---

## Step 11 – Preserve the Task Definition

The task definition was exported using:

```cmd
schtasks /query /tn "CompromisedLab-Persistence" /xml > C:\CompromisedWorkstationLab\task-definition.xml
```

This preserved the persistence configuration for forensic analysis.

---

## Step 12 – Establish Network Listener

A controlled TCP listener was created on:

```text
127.0.0.1:9091
```

The listener accepted a connection and read a harmless test message.

No external command-and-control system was involved.

---

## Step 13 – Generate Controlled Network Activity

PowerShell generated a TCP connection to:

```text
127.0.0.1:9091
```

and transmitted a harmless laboratory message.

The activity was designed to generate network telemetry for investigation.

---

## Step 14 – Review Sysmon Event ID 1

Sysmon Event ID 1 was reviewed for process creation.

Captured evidence showed a PowerShell process:

```text
C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
```

at approximately:

```text
18-08-2026 10:32:15
```

The displayed process evidence was used to establish PowerShell activity on the endpoint.

---

## Step 15 – Review Sysmon Event ID 3

Sysmon Event ID 3 was reviewed for network connections.

The captured event showed:

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

This event was unrelated to the controlled `127.0.0.1:9091` network test.

It was therefore treated as background endpoint activity and excluded from the simulated compromise chain.

---

## Step 16 – Review Defender Event ID 5007

Microsoft Defender Operational logs showed Event ID:

```text
5007
```

The event reported a configuration change involving:

```text
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\CompromisedWorkstationLab
```

Observed timestamp:

```text
18-08-2026 10:32:19
```

This directly supports the conclusion that the lab directory was added as a Defender exclusion.

---

## Step 17 – Correlate PowerShell and Defender Activity

PowerShell execution occurred around the Defender configuration change.

The resulting relationship was:

```text
PowerShell
      ↓
Add-MpPreference
      ↓
Defender Exclusion
      ↓
Event ID 5007
```

The activity was intentionally generated as part of the lab.

---

## Step 18 – Investigate in Wazuh

Wazuh Discover was searched using:

```text
agent.name: DESKTOP-9MMM37V
```

Additional investigative terms included:

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

The objective was to correlate authentication, process, persistence, and Defender events within the same endpoint timeline.

---

# Key Findings

- Wazuh Agent `001` was active.
- Endpoint `DESKTOP-9MMM37V` was under investigation.
- The active user was `desktop-9mmm37v\dell`.
- `C:\CompromisedWorkstationLab` was created as the controlled staging directory.
- A `CompromiseTest` user was created.
- Logon auditing was enabled during the laboratory activity.
- Security 4624/4625 events were observed, but the captured examples were for the machine account `DESKTOP-9MMM37V$`.
- A harmless PowerShell payload was created and executed.
- PowerShell used `ExecutionPolicy Bypass` during the controlled execution.
- `CompromisedLab-Persistence` was created as an AtLogOn scheduled task.
- The task definition was preserved in XML.
- A local TCP listener was staged on port `9091`.
- Defender Event ID 5007 confirmed a configuration change involving the lab directory.
- The endpoint already had several Defender protection features disabled before the lab modification.
- Sysmon Event ID 1 confirmed PowerShell process creation.
- The displayed Sysmon Event ID 3 belonged to Zoho Mail Desktop rather than the controlled network test.
- Wazuh provided centralized endpoint visibility.

---

# Evidence Correlation

| Evidence | Source | Observation | Assessment |
|---|---|---|---|
| Endpoint identity | PowerShell | `DESKTOP-9MMM37V` | Confirmed |
| User identity | PowerShell | `desktop-9mmm37v\dell` | Confirmed |
| Wazuh agent | Wazuh Manager | Agent `001` active | Confirmed |
| Defender baseline | PowerShell | Several protections already `False` | Pre-existing state |
| Test account | Windows | `CompromiseTest` created | Controlled activity |
| Logon telemetry | Security | 4624 / 4625 available | Authentication telemetry |
| 4624 account | Security | `DESKTOP-9MMM37V$` | Machine account |
| PowerShell execution | Sysmon 1 | `powershell.exe` observed | Confirmed |
| Persistence | Task Scheduler | `CompromisedLab-Persistence` | Controlled persistence |
| Task definition | XML | Task action preserved | Forensic artifact |
| Defender change | Defender 5007 | Lab path added as exclusion | Confirmed |
| Network telemetry | Sysmon 3 | Zoho Mail TCP connection | Unrelated background activity |
| Wazuh | Discover | Endpoint telemetry available | Centralized visibility |

---

# DFIR Analysis

The evidence forms a controlled multi-stage activity sequence involving account creation, PowerShell execution, scheduled-task persistence, Defender configuration modification, and network staging.

The strongest directly supported compromise-style indicators are the PowerShell execution, the scheduled-task persistence, and Defender Event ID 5007 showing the addition of the lab directory as an exclusion.

However, the evidence must be interpreted carefully. Defender Real-Time Protection, Behavior Monitor, and IOAV Protection were already disabled when the initial baseline was captured, so those states cannot be attributed to the simulation.

Similarly, the captured 4624 and 4625 events represent the machine account rather than `CompromiseTest`, and the displayed Sysmon Event ID 3 belongs to Zoho Mail Desktop rather than the controlled network listener.

Therefore, the lab demonstrates a **multi-stage compromise-style activity chain**, but not every stage is independently confirmed by the captured telemetry.

---

# Incident Assessment

The controlled activity successfully reproduced several behaviors commonly investigated during endpoint compromise:

```text
Account Creation
      ↓
PowerShell Execution
      ↓
Scheduled Task Persistence
      ↓
Defender Configuration Change
      ↓
Network Staging
```

The evidence supports the existence of these controlled activities.

The evidence does not establish:

- A real attacker
- A real external command-and-control connection
- A confirmed unauthorized `CompromiseTest` logon
- That the pre-existing Defender protection state was caused by the lab
- That the displayed Zoho Mail network event was related to the simulation

The correct DFIR classification is therefore:

**Controlled compromised-workstation simulation with multiple correlated security-relevant behaviors.**

---

# MITRE ATT&CK Context

The simulated behaviors provide contextual mapping to:

- `T1059.001 – Command and Scripting Interpreter: PowerShell`
- `T1053.005 – Scheduled Task/Job: Scheduled Task`
- `T1562.001 – Impair Defenses: Disable or Modify Tools`

The ATT&CK mapping is contextual because the activities were intentionally generated for the laboratory.

---

# Skills Practiced

- Compromised Endpoint Investigation
- Windows DFIR
- Multi-Stage Incident Reconstruction
- PowerShell Investigation
- Authentication Analysis
- Process Creation Analysis
- Scheduled-Task Persistence Analysis
- Defender Configuration Analysis
- Sysmon Event ID 1
- Sysmon Event ID 3
- Windows Event ID 4624
- Windows Event ID 4625
- Windows Event ID 4688
- Wazuh Discover
- Evidence Correlation
- Timeline Reconstruction
- Evidence Gap Analysis

---

# Outcome

Successfully reconstructed a controlled multi-stage workstation compromise scenario using Windows and Wazuh telemetry.

The investigation linked endpoint discovery, PowerShell execution, scheduled-task persistence, Defender configuration modification, and network staging while also demonstrating the importance of excluding unrelated telemetry and identifying pre-existing security conditions.

The lab reinforced a critical DFIR principle:

> A compromised-workstation conclusion should be based on a correlated evidence chain, not on the presence of one suspicious event.
