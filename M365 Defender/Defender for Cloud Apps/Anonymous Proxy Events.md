# Events peformed while connecting to a Proxy

### [+] Defender for Endpoint 
```
CloudAppEvents
| where IsAnonymousProxy == 1
| extend UserId = tostring(parse_json(RawEventData).UserId)
| summarize
     TotalActivities = count(),
     ActionsPerformed = make_set(ActionType),
     OSUsed = make_set(OSPlatform),
     IPsUsed = make_set(IPAddress)
     by AccountId, UserId
| project AccountId, UserId, TotalActivities, ActionsPerformed, OSUsed, IPsUsed
| sort by TotalActivities
```

### [+] Sentinel
```
CloudAppEvents
| where IsAnonymousProxy == 1
| extend UserId = tostring(parse_json(RawEventData).UserId)
| summarize
     TotalActivities = count(),
     ActionsPerformed = make_set(ActionType),
     OSUsed = make_set(OSPlatform),
     IPsUsed = make_set(IPAddress)
     by AccountId, UserId
| project AccountId, UserId, TotalActivities, ActionsPerformed, OSUsed, IPsUsed
| sort by TotalActivities
```
### [+] Description
This KQL query searches for anonymous proxy access in the cloud environment.

### [+] Recommended Actions
1. Recommended actions for this query include investigating the activities performed by the user associated with the anonymous proxy access and determining if any malicious activity was performed.
2. 

### [+] Resources
- Forked from directly from [@Bert-JanP](https://github.com/Bert-JanP), please give him credit and a follow!
