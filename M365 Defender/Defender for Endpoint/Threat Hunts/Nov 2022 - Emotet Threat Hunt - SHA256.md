# Nov 2022 - Emotet SHA256 IOC Threat Hunt 

**Source:** Ciscos Talos

**Feed:** https://blog.talosintelligence.com/emotet-coming-in-hot/

### Defender For Endpoint & Microsoft Sentinel
```
let Emotet = externaldata(sha256: string)[@"https://githubraw.com/Cisco-Talos/IOCs/main/2022/11/Emotet_parents.txt"] with (format="txt", ignoreFirstRecord=True);
DeviceFileEvents
| where SHA256 in (Emotetsha)
| project Timestamp, FileName, SHA256, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```
:exclamation: You will need to turn on M365 Data connector on Sentinel in order for this KQL to work. 


