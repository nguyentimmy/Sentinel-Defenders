# Nov 2022 - Emotet SHA256 IOC - Threat Hunt 

### [+] Defender for Endpoint & Microsoft Sentinel KQL
```
// This will search for the Indicators of Compromise (IOCs) in the form of SHA256 hashes within the link containing the TXT file.

let Emotet = externaldata(sha256: string)[@"https://githubraw.com/Cisco-Talos/IOCs/main/2022/11/Emotet_parents.txt"] with (format="txt", ignoreFirstRecord=True);
DeviceFileEvents
| where SHA256 in (Emotet)
| project Timestamp, FileName, SHA256, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```
:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
Emotet is a ubiquitous and well-known banking trojan that has evolved over the years to become a very successful modular botnet capable of dropping a variety of other threats. Even after a global takedown campaign in early 2021 disrupted the botnet, it reemerged later that year, rebuilding its infrastructure and becoming highly active in a short time.
Emotet is back again with a new campaign displaying many characteristics of older runs, including the use of Auto_Open macros inside XLS documents. Cisco Talos has observed an increased activity of spam distributing this new strain beginning in early November 2022,  and the volume of spam and Emotet infrastructure has been increasing since then to target multiple geographies around the world.

### [+] Resources 
- **Blog:** https://blog.talosintelligence.com/emotet-coming-in-hot/
- **IOC:** https://githubraw.com/Cisco-Talos/IOCs/main/2022/11/Emotet_parents.txt

