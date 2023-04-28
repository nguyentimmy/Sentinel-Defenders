# Potential Local Admin Account Creation

### [+] Defender for Endpoint
```
DeviceProcessEvents
| where ProcessCommandLine has "net user" and ProcessCommandLine has "net localgroup" or ActionType == 'UserAccountCreated'
| where ProcessCommandLine contains "administrators" or ProcessCommandLine contains "Admins"
| extend AccountName = extract("net user (.*?) /add", 1, ProcessCommandLine) // Extract the account name
| extend LocalGroupName = extract("net localgroup (.*?) ", 1, ProcessCommandLine) // Extract the local group name
| project Timestamp, DeviceName, DeviceId, ProcessCommandLine, AccountName, FileName, LocalGroupName, ReportId

```
###. Sentinel 
```
DeviceProcessEvents
| where ProcessCommandLine has "net user" and ProcessCommandLine has "net localgroup" or ActionType == 'UserAccountCreated'
| where ProcessCommandLine contains "administrators" or ProcessCommandLine contains "Admins"
| extend AccountName = extract("net user (.*?) /add", 1, ProcessCommandLine) // Extract the account name
| extend LocalGroupName = extract("net localgroup (.*?) ", 1, ProcessCommandLine) // Extract the local group name
| project TimeGenerated, DeviceName, DeviceId, ProcessCommandLine, AccountName, FileName, LocalGroupName, ReportId
```

:exclamation: *You MAY need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This alert is triggered when a process command line is detected that includes both "net user" and "net localgroup" commands, indicating a potential attempt to create a new user account and add it to a local administrative group. The query also checks if the command line contains "administrators" or "Admins", further narrowing the focus on potential privileged account creation events. Closely deals with MITRE T1136.001.

### [+] Potential Mitigation Steps
1. Investigate the user account and local group modification activity to determine if it was authorized or part of regular administrative tasks.
2. Review the user account that initiated the commands and verify if the user has the appropriate privileges to perform such actions. If not, consider revoking the user's elevated privileges.
3. If the activity is unauthorized or suspicious, reset the passwords for the affected user accounts and remove any unauthorized users from the local groups.

### [+] Resources 
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md
