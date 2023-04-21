# Lateral Movement Actions

### [+] Defender for Endpoint
**Query 1**
```
IdentityDirectoryEvents
| where ActionType == "Potential lateral movement path identified"
| project Timestamp, ActionType, AccountName, AccountDomain, DeviceName, ReportId
```
**Query 2**
```
IdentityDirectoryEvents
| where ActionType == "Potential lateral movement path identified"
| summarize count() by ActionType, AccountDomain, AccountDisplayName, AccountName
```
### [+] Sentinel
```
IdentityDirectoryEvents
| where ActionType == "Potential lateral movement path identified"
| project TimeGenerated, ActionType, AccountName, AccountDomain, DeviceName, ReportId
```
:exclamation: *You MAY need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This query may generate a lot of false positivies. But it's ideal to investigate any unsual activities. This query shows users and devices that may have some sort of lateral movement across a domain.
Lateral movement is a technique used in cyber attacks where a threat actor gains access to a single system within a network and uses that system as a pivot point to move laterally across the network in search of sensitive data or systems to compromise. This technique allows attackers to escalate their privileges and ultimately gain access to critical systems within the network.

### [+] Recommended Actions
1. As stated in the description, this query can generally output a lot of false positives, however in some scenario, it maybe important to investigate if there's an unusual amount of sign-ins or movement to particular domain. (Use Query 2 on Defender for endpoint for an example) 

### [+] Resources
- [What is Lateral Movement?](https://www.crowdstrike.com/cybersecurity-101/lateral-movement/)
- [How to investigate Lateral Movement on Defender](https://learn.microsoft.com/en-us/defender-for-identity/understand-lateral-movement-paths)
