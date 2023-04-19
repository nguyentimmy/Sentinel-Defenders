# Suspicious Local User & Group Modification

### Defender for Endpoint & Microsoft Sentinel KQL
```
DeviceProcessEvents
| where ProcessCreationTime > ago(1d)
| where ProcessCommandLine has "net user" and ProcessCommandLine has "net localgroup"
| project ProcessCreationTime, ProcessCommandLine, DeviceName, AccountName, FileName
```
:exclamation: You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work. 

### Description 
This alert is triggered when there are events indicating an attempt to add or modify a user account using "net user" command and subsequently adding that user to a local group, such as local administrators group, using "net localgroup" command within the last 24 hours. This activity may indicate unauthorized changes to user accounts and local group memberships, which could potentially lead to privilege escalation or unauthorized access.


### Potential Mitigation Steps
1. Investigate the user account and local group modification activity to determine if it was authorized or part of regular administrative tasks.
2. Review the user account that initiated the commands and verify if the user has the appropriate privileges to perform such actions. If not, consider revoking the user's elevated privileges.
3. If the activity is unauthorized or suspicious, reset the passwords for the affected user accounts and remove any unauthorized users from the local groups.


