# Users added to Sudoers

### [+] Defender for Endpoint & Microsoft Sentinel KQL
```
let Commands = dynamic([@"usermod -aG sudo", @"usermod -a -G sudo"]);
DeviceProcessEvents
| extend RegexGroupAddition = extract("adduser(.*) sudo", 0, ProcessCommandLine)
| where ProcessCommandLine has_any (Commands) or isnotempty(RegexGroupAddition)
```
:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This rule helps identify potential attempts to add users to the sudo group, which may indicate an attempt to escalate privileges or perform unauthorized actions.

### [+] Potential Mitigation Steps
1. Investigate the user account and local group modification activity to determine if it was authorized or part of regular administrative tasks.
2. Review the user account that initiated the commands and verify if the user has the appropriate privileges to perform such actions. If not, consider revoking the user's elevated privileges.
3. If the activity is unauthorized or suspicious, reset the passwords for the affected user accounts and remove any unauthorized users from the local groups.

### [+] Resources 
- https://atomicredteam.io/persistence/T1098/
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md
