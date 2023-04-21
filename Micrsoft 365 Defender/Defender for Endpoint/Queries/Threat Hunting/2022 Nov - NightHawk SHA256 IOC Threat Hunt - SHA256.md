# 2022 Nov - NightHawk SHA256 IOC - Threat Hunt 

### [+] Defender for Endpoint 
```
// This will hunt for the SHA256 hashes within the query.

let NighthawkRat = dynamic(['0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988', '9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8', '38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf', 'f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e', 'b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94']);
DeviceFileEvents
| where SHA256 in (NighthawkRat)
| extend FilePath = strcat(FolderPath, FileName) 
| extend InitiatingProcessName = tostring(split(InitiatingProcessCommandLine, " ")[0]) 
| project Timestamp, DeviceName, DeviceID, FileName, FolderPath, FilePath, InitiatingProcessCommandLine, InitiatingProcessName, ReportID
```
### [+] Sentinel
```
// This will hunt for the SHA256 hashes within the query.

let NighthawkRat = dynamic(['0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988', '9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8', '38881b87826f184cc91559555a3456ecf00128e01986a9df36a72d60fb179ccf', 'f3bba2bfd4ed48b5426e36eba3b7613973226983a784d24d7a20fcf9df0de74e', 'b775a8f7629966592cc7727e2081924a7d7cf83edd7447aa60627a2b67d87c94']);
DeviceFileEvents
| where SHA256 in (NighthawkRat)
| extend FilePath = strcat(FolderPath, FileName) 
| extend InitiatingProcessName = tostring(split(InitiatingProcessCommandLine, " ")[0]) 
| project TimeGenerated, DeviceName, DeviceID, FileName, FolderPath, FilePath, InitiatingProcessCommandLine, InitiatingProcessName, ReportID
```
:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
Created in late 2021 by MDSec, the tool is best described as an advanced C2 framework, which functions like Cobalt Strike and Brute Ratel as a commercially distributed remote access trojan (RAT) designed for legitimate use.
Nighthawk implements a technique that can prevent endpoint detection products from receiving notifications for newly loaded DLLs in the current process context via callbacks that were registered with LdrRegisterDllNotification,” the report explained. “This technique is enabled by the clear-dll-notifications option

### [+] Resources 
- [Blog](https://www.infosecurity-magazine.com/news/experts-threat-actors-red-team/)
- [IOC](https://raw.githubusercontent.com/fboldewin/YARA-rules/master/nighthawk.yar)

