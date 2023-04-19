# Smart Screen Prompt Detection 

### [+] Defender for Endpoint & Microsoft Sentinel KQL
```
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType has_any('SmartScreenAppWarning', 'SmartScreenUrlWarning')
| extend SmartScreenDetection = iif(ActionType == "SmartScreenUrlWarning", parse_url(RemoteUrl).Host, FileName)
| project Timestamp, DeviceName, SmartScreenDetection, ActionType, InitiatingProcessCommandLine
```
:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
If this alert is triggered, it is recommended to investigate the potentially malicious application or website triggering the warning and take appropriate action to mitigate any risks. 

### [+] Recommended Actions
1. Investigate the potentially malicious application or website triggering the SmartScreen warning.
2. Scan the affected device(s) for signs of compromise, such as malware or unauthorized access.
3. Train users on safe browsing practices and the importance of avoiding potentially malicious websites or applications.
