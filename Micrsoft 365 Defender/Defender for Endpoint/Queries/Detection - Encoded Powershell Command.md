# Encoded Powershell
### [+] Defender for Endpoint
```
let alertid=
AlertInfo
| where Title == @"Suspicious PowerShell command line"
| distinct AlertId;
AlertEvidence
| where AlertId in (alertid)
| where EntityType == "Process"
| extend EncodedCommand = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, ProcessCommandLine)
| where EncodedCommand != ""
| extend DecodedCommand = base64_decode_tostring(EncodedCommand)
| where DecodedCommand != ""
| project Timestamp, DeviceName, DeviceID, AlertId, ProcessCommandLine, DecodedCommand, ReportID
```
### [+] Sentinel 
```
SecurityAlert
| where AlertName == "Suspicious PowerShell command line"
| mv-expand todynamic(Entities)
| extend CommandLine = tostring(Entities.CommandLine)
//This particular query looks for only encoded Powershell commands, if you want all Powershell commands just remove the lines below
| extend EncodedCommand = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, CommandLine)
| where EncodedCommand != ""
| extend DecodedCommand = base64_decode_tostring(EncodedCommand)
| where DecodedCommand != ""
| project TimeGenerated, CompromisedEntity, AlertName, CommandLine, DecodedCommand
```



### [+] Description 
KQL query searches for suspicious PowerShell command lines within security alerts. It extracts encoded PowerShell commands, decodes them, and outputs the decoded command lines that were found. 

### [+] Recommended Actions
1. Investigate the compromised entity: The query identifies suspicious PowerShell commands, which may indicate malicious activity. Investigate the compromised entity (e.g. user account, host) associated with the alert to determine the scope and severity of the incident.
2. Analyze the command line and decoded command: Review the PowerShell command line and decoded command to identify the specific actions taken by the attacker. This information can help in understanding the purpose of the attack, potential data exfiltration, and any other malicious activities.
4. Review PowerShell usage: Review the usage of PowerShell in your environment to identify any suspicious activity. Look for patterns in the command lines, frequency of use, and unusual network activity.
5. Update security policies: Update your security policies to block the usage of known malicious PowerShell commands and techniques. This can help prevent future attacks and reduce the risk of compromise.nd browsing of torrent-related websites, and consider implementing more stringent controls if necessary.

### [+] Resources 
- Forked directly from [@Reprise99](https://hackcur.io/onion-and-on-and-on-hacking-the-internet-with-tor/#:~:text=This%20grants%20Tor%20users%20extremely,content%20restrictions%20and%20state%20censorship.) please give him credit and a follow!

