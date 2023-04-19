# Smart Screen Override 

### [+] Defender for Endpoint & Microsoft Sentinel KQL
```
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "SmartScreenUserOverride
```
:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This alert triggers when SmartScreen on a Windows device has been overridden by a user. Recommended to investigate the potentially malicious application or website triggering the warning and take appropriate action to mitigate any risks. 

### [+] Recommended Actions
1. Investigate the potentially malicious application or website triggering the SmartScreen warning. Run an anti-virus scan or analyze the logs.
2. If malicious file is found, contact the end user immediately to remove the application or software. Isolate the device if needed. 
3. Train users on safe browsing practices and the importance of avoiding potentially malicious websites or applications.

### [+] Resources
- [What is Windows Smart Screen?](https://learn.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-smartscreen/microsoft-defender-smartscreen-overview)
