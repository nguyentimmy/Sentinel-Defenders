# Suspicious Use of Desktopimgdownldr.exe with Lockscreenurl Process

### [+] Defender for Endpoint KQL
```
DeviceProcessEvents
| where FileName contains "desktopimgdownldr.exe"
| where ProcessCommandLine contains "/lockscreenurl:"
| where InitiatingProcessFileName != "explorer.exe" and InitiatingProcessFileName != "svchost.exe"
| where InitiatingProcessAccountName != "SYSTEM"
| where Timestamp > ago(1d)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FileName, ProcessCommandLine, ReportId
```

### [+] Microsoft Sentinel KQL
```
DeviceProcessEvents
| where FileName contains "desktopimgdownldr.exe"
| where ProcessCommandLine contains "/lockscreenurl:"
| where InitiatingProcessFileName != "explorer.exe" and InitiatingProcessFileName != "svchost.exe"
| where InitiatingProcessAccountName != "SYSTEM"
| where TimeGenerated > ago(1d)
| project TimeFGenerated, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, FileName, ProcessCommandLine, ReportId
```

### [+] Description 
Could abuse this executable by using it to execute malicious code or payloads, making it a security risk. Hackers could potentially replace the original desktopimgdownldr.exe. Desktopimgdownldr.exe to download a malicious file instead of a desktop or lockscreen background img. The process that actually makes the TCP connection and creates the file on the disk is a svchost process (“-k netsvc -p -s BITS”) and not desktopimgdownldr.exe

### [+] Recommended Actions

1. Investigate the source of the command line containing "/lockscreenurl:" to determine if it is legitimate or not.
2. Determine if the desktopimgdownldr.exe file is legitimate or if it has been tampered with. Check the digital signature and file properties to ensure it is a trusted Microsoft file
3. Block the execution of the desktopimgdownldr.exe file if it is determined to be malicious or unnecessary for business purposes.

### [+] Resources 
- https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md
