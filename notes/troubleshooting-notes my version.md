# Troubleshooting Notes

## Issue 1 – Defender Protection Was Already Partially Disabled

### Observation

The initial `Get-MpComputerStatus` baseline showed:

```text
RealTimeProtectionEnabled : False
BehaviorMonitorEnabled    : False
IoavProtectionEnabled     : False
```

### Interpretation

These settings existed before the simulated Defender exclusion was added.

### Resolution

Treat them as **pre-existing endpoint state**.

Do not claim that the laboratory changed these settings.

---

## Issue 2 – Logon Auditing Was Initially Disabled

### Observation

The `auditpol` check showed:

```text
Logon
No Auditing
```

### Impact

Authentication telemetry could be incomplete.

### Resolution

The lab enabled successful and failed logon auditing:

```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

The change was performed to improve telemetry for the exercise.

---

## Issue 3 – 4624 / 4625 Events Did Not Show CompromiseTest

### Observation

The captured authentication events showed:

```text
Account Name:
DESKTOP-9MMM37V$

Security ID:
SYSTEM
```

### Interpretation

These are machine/system authentication events.

### Resolution

Do not attribute these events to `CompromiseTest`.

Document the authentication evidence gap.

---

## Issue 4 – Sysmon Event ID 3 Showed Zoho Mail

### Observation

The captured network connection event identified:

```text
Zoho Mail - Desktop.exe
```

### Interpretation

This was unrelated background network activity.

### Resolution

Exclude the event from the simulated compromise chain.

The correct investigation principle is:

```text
Same host + similar time
```

does not automatically mean:

```text
Same incident activity
```

---

## Issue 5 – Controlled Network Activity Was Not Clearly Visible

### Problem

The local `127.0.0.1:9091` network activity was generated during the lab, but the captured Sysmon Event ID 3 evidence did not show it.

### Resolution

Record the activity as a controlled test but do not claim Sysmon captured it unless the corresponding Event ID 3 contains matching:

- Process
- PID
- Destination
- Port
- Timestamp

---

## Issue 6 – Wazuh Search Returned Unrelated Events

### Problem

Broad searches for the workstation returned many unrelated Windows events.

### Resolution

Narrow searches using:

```text
agent.name: DESKTOP-9MMM37V
```

Then add specific terms:

```text
powershell.exe
```

```text
CompromisedLab-Persistence
```

```text
5007
```

Use the exact investigation time window where possible.

---

## Issue 7 – Defender Event 5007 Shows SYSTEM

### Observation

The Defender Event ID 5007 displayed:

```text
User:
SYSTEM
```

### Interpretation

This does not mean the `SYSTEM` account necessarily initiated the configuration change interactively.

Windows security components can record configuration changes under system context.

### Resolution

Use process creation and command-line evidence to investigate the process that performed the change.

Do not attribute the action solely from the Defender event's User field.

---

## Issue 8 – Multiple Process Creation Events Around the Same Time

### Problem

Many Sysmon Event ID 1 events appeared around the incident window.

### Cause

Normal Windows background activity generates large amounts of process telemetry.

### Resolution

Correlate using:

- Process image
- Process ID
- Parent process
- Command line
- Timestamp
- User

Do not treat every nearby Event ID 1 as part of the compromise.

---

## Issue 9 – Scheduled Task Was Present but Authentication Was Not Confirmed

### Problem

The persistence mechanism existed, but a corresponding CompromiseTest logon was not demonstrated.

### Resolution

Separate:

```text
Persistence Exists
```

from:

```text
User Authenticated
```

The two are separate evidence questions.

---

## Issue 10 – Evidence Chain Was Incomplete

### Observation

The lab generated several stages, but not every stage had a directly matching screenshot or telemetry event.

### Resolution

Document the evidence chain as:

```text
Confirmed Evidence
+
Supporting Evidence
+
Unrelated Evidence
+
Evidence Gaps
```

This prevents overstatement of the compromise narrative.

---

