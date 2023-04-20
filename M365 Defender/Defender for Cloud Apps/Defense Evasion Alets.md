# Potiental CobaltStrike Activity 

### [+] Defender for Endpoint 
```
DeviceEvents
let CobaltStrike = dynamic(["beacon.exe", "cobaltstrike.exe"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (CobaltStrike)
| project Timestamp, DeviceName, DeviceID, AccountName, AccountDomain, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ReportID
```

### [+] Resources
- Forked from [Bert-JanP](https://github.com/Bert-JanP)
