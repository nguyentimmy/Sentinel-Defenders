# Potential Privileged Account Creation 

### [+] Defender for Endpoint & Microsoft Sentinel KQL
```
DeviceEvents
| where ActionType startswith 'Asr' and ActionType contains 'Blocked' 
| extend RuleId = extract("AsrRuleId\\[(.*?)\\]", 1, AdditionalFields)
| extend RuleName = extract("AsrRuleName\\[(.*?)\\]", 1, AdditionalFields)
| project Timestamp, DeviceName, ActionType, RuleId, RuleName, FileName, InitiatingProcessCommandLine, RemoteUrl
| order by Timestamp desc
```
:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This rule uses the DeviceEvents table in Microsoft Defender for Endpoint to filter for ASR events where any rule was blocked. Not really the ideal rule to custom detection or analytics rule to create, because it will generate a lot of noise. 
