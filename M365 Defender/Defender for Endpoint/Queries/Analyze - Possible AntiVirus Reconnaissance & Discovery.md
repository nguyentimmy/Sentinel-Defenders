# Possible AntiVirus Reconnaissance & Discovery 

### [+] Defender for Endpoint KQL
```
DeviceProcessEvents
| where FileName =~ "WMIC.exe"
| where ProcessCommandLine contains "AntiVirusProduct"
| project Timestamp, DeviceName, DeviceId, ReportId, ActionType, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, AccountUpn, InitiatingProcessFileName
| summarize count() by DeviceName, DeviceId, ProcessCommandLine, ActionType
| sort by count_ desc
```

### Microsoft Sentinel KQL
```
DeviceProcessEvents
| where FileName =~ "WMIC.exe"
| where ProcessCommandLine contains "AntiVirusProduct"
| project TimeGenerated, DeviceName, DeviceId, ReportId, ActionType, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, AccountUpn, InitiatingProcessFileName
| summarize count() by DeviceName, DeviceId, ProcessCommandLine, ActionType
| sort by count_ desc
```
:exclamation: *You MAY need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This query detects suspicious WMIC executions with the command "AntiVirusProduct" in the process command line. The use of WMIC can be a sign of suspicious activity as it can be used to execute commands remotely and is often used by attackers. This rule specifically looks for the use of WMIC to query the list of AntiVirusProduct, which could be an indicator of an attacker attempting to find ways to bypass antivirus protection.
If the command `wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName, displayVersion` appears in the search, it maybe a possibility that an attacker may try to retrieve the information on the anti-virus to evade detection.

### [+] Recommended Actions
1. Investigate the device to determine if the WMIC execution is legitimate or if it is a sign of malicious activity.
2. If the execution is deemed suspicious, take appropriate action to contain and remediate the device, such as isolating the device from the network, performing a full system scan for malware, and reviewing other security events from the device to determine if there are any other indicators of compromise.

### [+] Resources
- [T1047 - Windows Management Instrumentation](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md)
