# Potiental CobaltStrike Activity 

### [+] Defender for Endpoint & Microsoft Sentinel KQL
```
DeviceEvents
let CobaltStrike = dynamic(["beacon.exe", "cobaltstrike.exe"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (CobaltStrike)
| project Timestamp, DeviceName, DeviceID, AccountName, AccountDomain, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ReportID
```

### [+] Microsoft Sentinel KQL
```
DeviceEvents
let CobaltStrike = dynamic(["beacon.exe", "cobaltstrike.exe"]);
DeviceProcessEvents
| where TimeGenerated > ago(1d)
| where ProcessCommandLine has_any (CobaltStrike)
| project TimeGenerated, DeviceName, DeviceID, AccountName, AccountDomain, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ReportID
```
:exclamation: *You MAY need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This query is designed to detect the presence of Cobalt Strike, a commercially available penetration testing tool that is also commonly used by attackers for post-exploitation activities. The query searches for process events containing known Cobalt Strike executables and filters out false positives by examining the process command line. 
**Detecting CobaltStrike is a lot more complex, as it comes in different forms. This alert will generally pick up any device that is pontientally running or downloading an exe of cobaltstrike.**

### [+] Recommended Actions
1. Investigate the device where the Colbalt-related activity was detected to determine the scope and severity of the potential threat.
2. Identify the root cause of the Colbalt-related activity and take appropriate actions to remediate the issue.
3. Review the user and computer accounts, group memberships, and other AD objects accessed by the detected Colbalt-related activity to ensure that they have not been compromised or misused.
4. Check for any lateral movement or privilege escalation that may have been attempted using Bloodhound and take appropriate actions to prevent further damage.
5. If necessary, isolate the affected device from the network to prevent further potential harm.

### [+] Resources
- [What is Cobalt Strike?](https://www.cobaltstrike.com/)
