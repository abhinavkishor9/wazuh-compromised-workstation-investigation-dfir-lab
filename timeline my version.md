# Investigation Timeline

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
