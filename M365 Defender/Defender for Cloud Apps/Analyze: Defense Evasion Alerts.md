# Defense Evasion Alerts

### [+] Defender for Endpoint 
```
 CloudAppEvents
 | where ActionType == 'DefenseEvasion'
 | extend
      AlertUri = parse_json(RawEventData).AlertUri,
      AlertDisplayName = parse_json(RawEventData).AlertDisplayName,
      AlertSeverity = parse_json(RawEventData).AlertSeverity
| project Timestamp,  AlertDisplayName, AlertSeverity, AccountDisplayName, AlertUri
```

### [+] Sentinel
```
CloudAppEvents
| where ActionType == 'DefenseEvasion'
| extend
     AlertUri = parse_json(RawEventData).AlertUri,
     AlertDisplayName = parse_json(RawEventData).AlertDisplayName,
     AlertSeverity = parse_json(RawEventData).AlertSeverity
| project AlertUri, AlertDisplayName, AlertSeverity
```
:exclamation: *You MAY need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*


### [+] Description
This KQL query searches through Cloud App Security events to find any instances where a Defense Evasion action was taken.

### [+] Recommended Actions
1. Based on the information gathered by this query, recommended action items might include reviewing any alerts with a high AlertSeverity rating, investigating the AccountDisplayName associated with the event to determine if any further actions are needed, 
2. Examine the AlertUri to understand the nature of the Defense Evasion action and any potential impact on the organization's security posture.


### [+] Resources
- Forked from [@Bert-JanP](https://github.com/Bert-JanP)
