# Communication to a Phishing Domain
### [+] Sentinel 
```
let domain=
    SecurityAlert
    | where TimeGenerated > ago (1d) // Modify time if needed
    | where AlertName startswith "Communication with possible phishing domain"
    | mv-expand todynamic(Entities)
    | extend DomainName = tostring(Entities.DomainName)
    | where isnotempty(DomainName)
    | distinct DomainName;
DeviceNetworkEvents
| where TimeGenerated > ago (1d) // Modify time if needed
| where RemoteUrl in~ (domain)
| project
    TimeGenerated,
    ActionType,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    LocalIP,
    RemoteIP,
    RemoteUrl,
    RemotePort
```
:exclamation: *You WILL need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint**  and **Security Alerts** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
Designed to detect potential communication with phishing domains in your environment. 

### [+] Recommended Actions
1. Investigate the identified domain name(s) for possible phishing activities.
2. Review the affected device(s) and user(s) for any signs of compromise or malicious activities.
3. Block or restrict access to the identified domain name(s) and IP addresses.
4. Review and enforce security controls and policies related to email and web browsing.
5. Educate users on how to identify and report potential phishing emails or websites.

### [+] Resources 
- Forked directly from [@Reprise99](https://hackcur.io/onion-and-on-and-on-hacking-the-internet-with-tor/#:~:text=This%20grants%20Tor%20users%20extremely,content%20restrictions%20and%20state%20censorship.) please give him credit and a follow!
