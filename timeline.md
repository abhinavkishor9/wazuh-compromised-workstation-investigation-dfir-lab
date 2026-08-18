# Investigation Timeline

## Lab 54 – Compromised Workstation Investigation

| Time | Activity | Evidence | Assessment |
|---|---|---|---|
| 06:08–08:41 | Wazuh Syscheck activity | Wazuh | Endpoint baseline |
| 09:48 | Host/user discovery | PowerShell | Endpoint identification |
| 09:48 | Investigation workspace created | PowerShell | Lab staging |
| 09:48–09:58 | Defender baseline collected | PowerShell | Pre-existing security state |
| 09:58 | `CompromiseTest` account created | Windows | Controlled activity |
| 10:00 | Logon auditing activity | `auditpol` / Security | Authentication telemetry preparation |
| 10:15 | PowerShell payload created/executed | PowerShell | Controlled execution |
| 10:32:15 | PowerShell process observed | Sysmon Event ID 1 | Process telemetry |
| 10:32:19 | Defender Event ID 5007 | Defender | Exclusion added |
| 10:32 | Scheduled-task persistence | Task Scheduler | Controlled persistence |
| 10:42 | Network staging / telemetry review | PowerShell / Sysmon | Controlled network activity |
| Investigation | Wazuh correlation | Wazuh Discover | Centralized analysis |

---

# Baseline Timeline

## 06:08–08:41

Wazuh Syscheck activity provided an earlier endpoint baseline.

This established that the Wazuh agent was actively monitoring the workstation before the laboratory activity.

---

## 09:48

The workstation and current user were identified:

```text
Host:
DESKTOP-9MMM37V

User:
desktop-9mmm37v\dell
```

The investigation workspace was created:

```text
C:\CompromisedWorkstationLab
```

---

## 09:48–09:58

Defender baseline information was collected.

Observed pre-existing state:

```text
AMServiceEnabled: True
AntivirusEnabled: True
RealTimeProtectionEnabled: False
BehaviorMonitorEnabled: False
IoavProtectionEnabled: False
```

Important:

These disabled protection states existed before the laboratory Defender exclusion was added.

---

# Account Timeline

## 09:58

The controlled account:

```text
CompromiseTest
```

was created.

The account was used only for laboratory simulation.

---

## 10:00

Logon auditing was configured.

A Security Event ID 4625 was later observed, but the captured event referenced:

```text
DESKTOP-9MMM37V$
```

rather than `CompromiseTest`.

Therefore, the authentication evidence does not establish a CompromiseTest login.

---

# Execution Timeline

## 10:15

The controlled PowerShell payload was staged and executed.

The resulting execution record identified:

```text
Host:
DESKTOP-9MMM37V

User:
desktop-9mmm37v\dell
```

PowerShell execution used:

```text
ExecutionPolicy Bypass
```

This created an investigation-relevant execution indicator.

---

# Persistence Timeline

The scheduled task:

```text
CompromisedLab-Persistence
```

was created with an AtLogOn trigger.

The task executed:

```text
powershell.exe
```

with:

```text
-NoProfile -File C:\CompromisedWorkstationLab\payload.ps1
```

The task definition was preserved in:

```text
C:\CompromisedWorkstationLab\task-definition.xml
```

---

# Defender Timeline

## 18-08-2026 10:32:19

Microsoft Defender Event ID 5007 recorded a configuration change.

Observed registry path:

```text
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\CompromisedWorkstationLab
```

Assessment:

The laboratory directory was added as a Defender exclusion.

This is directly supported by the captured Event ID 5007.

---

# Sysmon Timeline

## 18-08-2026 10:32:15

Sysmon Event ID 1 recorded:

```text
C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
```

Assessment:

PowerShell process creation was observed.

---

## 18-08-2026 10:42

A Sysmon Event ID 3 was observed.

The displayed event belonged to:

```text
Zoho Mail - Desktop.exe
```

using:

```text
Protocol: tcp
Initiated: true
```

Assessment:

This was unrelated background network activity and was excluded from the simulated compromise chain.

---

# Wazuh Timeline

The Wazuh agent was active throughout the investigation.

Endpoint:

```text
DESKTOP-9MMM37V
```

Agent:

```text
001
```

Wazuh was used to correlate:

- Endpoint activity
- PowerShell
- Defender changes
- Scheduled-task activity
- Windows security events

---

# Incident Reconstruction

```text
Endpoint Identified
        ↓
Investigation Workspace Created
        ↓
Defender Baseline Captured
        ↓
CompromiseTest Created
        ↓
PowerShell Payload Executed
        ↓
Scheduled Task Persistence Created
        ↓
Defender Exclusion Added
        ↓
Controlled Network Activity Staged
        ↓
Windows / Sysmon Telemetry Reviewed
        ↓
Wazuh Correlation
        ↓
Incident Assessment
```

---

# Evidence Validation

The timeline contains both directly confirmed and limited evidence.

### Directly Supported

```text
CompromiseTest account creation
PowerShell payload creation
PowerShell execution
Scheduled-task persistence
Defender exclusion
Sysmon Event ID 1
Wazuh endpoint visibility
```

### Requires Caution

```text
4624 / 4625 authentication events
```

because the captured events show the machine account rather than `CompromiseTest`.

### Excluded From Compromise Chain

```text
Sysmon Event ID 3
Zoho Mail - Desktop.exe
```

because it represents unrelated background network activity.

---

# Final Timeline Assessment

The evidence establishes a controlled sequence containing:

```text
Execution
+
Persistence
+
Security Configuration Change
+
Network Staging
```

The evidence does not establish an actual external attacker or malicious command-and-control session.

The appropriate forensic description is:

**Controlled multi-stage compromised-workstation simulation with correlated execution, persistence, and security-tool modification evidence, plus documented telemetry limitations.**
