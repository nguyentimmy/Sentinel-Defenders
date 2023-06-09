# Users added to Sudoers

### [+] Defender for Endpoint KQL
```
let Sudo = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
DeviceProcessEvents
| extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
| where ProcessCommandLine has_any (Sudo) or isnotempty(RegexGroupAddition)
| project Timestamp, DeviceName, DeviceId, ActionType, InitiatingProcessCommandLine, ReportId
```

### [+] Microsoft Sentinel KQL
```
let Sudo = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
DeviceProcessEvents
| extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
| where ProcessCommandLine has_any (Sudo) or isnotempty(RegexGroupAddition)
| project TimeGenerated, DeviceName, DeviceId, ActionType, InitiatingProcessCommandLine, ReportId
```

:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This rule helps identify potential attempts to add users to the sudo group, which may indicate an attempt to escalate privileges or perform unauthorized actions. Deals closely with MITRE T1136.001.

### [+] Potential Mitigation Steps
1. Investigate the user account and local group modification activity to determine if it was authorized or part of regular administrative tasks.
2. Review the user account that initiated the commands and verify if the user has the appropriate privileges to perform such actions. If not, consider revoking the user's elevated privileges.
3. If the activity is unauthorized or suspicious, reset the passwords for the affected user accounts and remove any unauthorized users from the local groups.

### [+] Resources 
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1098/T1098.md
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md
