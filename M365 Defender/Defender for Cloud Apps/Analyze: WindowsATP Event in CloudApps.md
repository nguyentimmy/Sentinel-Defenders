# WindowsATP Event in CloudApps

### [+] Defender for Endpoint 
```
CloudAppEvents
| where ActionType == "AtpDetection"
| extend
     DetectionMethod = parse_json(RawEventData).DetectionMethod,
     EventDeepLink = parse_json(RawEventData).EventDeepLink,
     FileData = parse_json(RawEventData).FileData
| project Timestamp, ActionType, Application, DetectionMethod, FileData, EventDeepLink
```

### [+] Sentinel
```
CloudAppEvents
| where ActionType == "AtpDetection"
| extend
     DetectionMethod = parse_json(RawEventData).DetectionMethod,
     EventDeepLink = parse_json(RawEventData).EventDeepLink,
     FileData = parse_json(RawEventData).FileData
| project TimeGenerated, ActionType, Application, DetectionMethod, FileData, EventDeepLink
```
### [+] Description
"ATP" stands for "Advanced Threat Protection", which is a security feature in Microsoft 365 that can detect and respond to advanced threats, including malware. However, it is also possible that other types of security events related to ATP could trigger this query

### [+] Recommended Actions
1. If a malware is detected in any results, it is recommended to investigate the affected devices and isolate them from the network to prevent the spread of the malware.


### [+] Resources
- Forked from directly from [@Bert-JanP](https://github.com/Bert-JanP), with bit of modification, please give him credit and a follow!
