# ASR Event Count by Device and User

### [+] Defender for Endpoint & Microsoft Sentinel KQL
```
DeviceEvents
| where ActionType startswith "Asr"
| extend RuleId = extract("AsrRuleId\\[(.*?)\\]", 1, AdditionalFields)
| extend RuleName = extract("AsrRuleName\\[(.*?)\\]", 1, AdditionalFields)
| extend UserSid = extract("UserSid\\[(.*?)\\]", 1, AdditionalFields)
| summarize Count = count() by DeviceName, ActionType, RuleId, RuleName, AccountName
| sort by Count desc
```
:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Descriptions
Counts Attack Surface Reduction (ASR) events by device and user in your environment. ASR rules help prevent malware and other potentially malicious activities by blocking certain actions or behaviors. By monitoring ASR events, you can quickly identify potentially suspicious activity and take necessary actions to mitigate the risk.

### [+] Recommended Actions 
1. Review the results of this rule to identify devices and users that have triggered the most ASR events. 
2. Investigate the users with the highest count/events and take necessary actions to remediate any potentially malicious activity. Ideally you can investigate the top 10 devices first, could be possible they are high risk. 
3. Review the ASR rules that were triggered and evaluate whether they should be modified to improve their effectiveness. 
4. You may also want to review other security-related events and logs to determine the scope and impact of the event
