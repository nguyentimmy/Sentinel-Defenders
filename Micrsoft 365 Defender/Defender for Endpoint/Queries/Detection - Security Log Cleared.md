# Security Log Cleared 

### [+] Defender for Endpoint 
```
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == 'SecurityLogCleared'
| project Timestamp, DeviceName, DeviceId, ActionType, LocalIP, ReportId

```

### [+] Sentinel 
```
// Results seems to be better on Defender
DeviceEvents
| where TimeGenerated > ago(1d)
| where ActionType == 'SecurityLogCleared'
| project TimeGenerated, DeviceName, DeviceId, ActionType, LocalIP, ReportId
```

### [+] Description 
This detection monitors for security logs being cleared on devices, which could indicate an attempt to cover up malicious activity or hide unauthorized access to a system.

### [+] Recommended Actions

1. When this alert is triggered, investigate the reason for the cleared security logs, ask the user if this was authorized. 
2. If not authorized, try to review the logs before they were cleared, as well as any other logs on the device, to determine if there was any suspicious activity or unauthorized access. 
3. Identify the source of the cleared logs, and take appropriate actions such as removing any malicious software, changing passwords, and reviewing user accounts and access rights.

### [+] Resources 
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md
