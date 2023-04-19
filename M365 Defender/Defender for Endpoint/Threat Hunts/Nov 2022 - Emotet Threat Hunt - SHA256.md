# Emotet SHA256 IOC Threat Hunt - Nov 2022

#### Source: Ciscos Talos 
#### Feed information: https://blog.talosintelligence.com/emotet-coming-in-hot/

### Defender For Endpoint & Microsoft Sentinel
```
let Emotet = externaldata(sha256: string)[@"https://githubraw.com/Cisco-Talos/IOCs/main/2022/11/Emotet_parents.txt"] with (format="txt", ignoreFirstRecord=True);
DeviceFileEvents
| where SHA256 in (Emotetsha)
| project Timestamp, FileName, SHA256, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```
