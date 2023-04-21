# Outdated Devices

### [+] Defender for Endpoint & Sentinel 
```
CloudAppEvents
| where ActionType == "FileMalwareDetected"
| extend FileName = parse_json(RawEventData).['SourceFileName']
| extend SiteUrl = parse_json(RawEventData).['SiteUrl']
| extend VirusVendor = parse_json(RawEventData).['VirusVendor']
| extend VirusInfo = parse_json(RawEventData).['VirusInfo']
| project Timestamp, Application, VirusInfo, ObjectName, FileName, VirusVendor, IPAddress
```
:exclamation: *You MAY need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description
This KQL query looks at Cloud App Events to identify devices with outdated operating systems. It filters for events where the user agent tags contain the phrase "Outdated operating system", then summarizes the count of these events by OS platform.

### [+] Recommended Actions
1. Identify devices with outdated operating systems found in the CloudAppEvents logs.
2. Develop a plan to upgrade the operating systems to reduce the risk of vulnerabilities being exploited.
3. Utilize endpoint protection solutions and keep it up-to-date to detect and prevent threats from outdated operating systems.
4. Educate users on the importance of keeping their devices and operating systems updated to avoid potential security risks.

### [+] Resources
- Forked from directly from [@Bert-JanP](https://github.com/Bert-JanP), with a few modifications, please give him credit and a follow!
