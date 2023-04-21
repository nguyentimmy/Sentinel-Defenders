# Suspected Shadow Copy Deletion

### [+] Defender for Endpoint KQL
```
let ShadowCopyDeletion = dynamic([@'vssadmin.exe delete shadows /all /quiet', 
@'wmic.exe shadowcopy delete', @'wbadmin delete catalog -quiet', 
@'Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}',
@'del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk', 
@'wbadmin delete systemstatebackup -keepVersions:0', 
@'schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable', 
@'schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /enable >nul 2>&1', 
@'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f', 
@'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /f >nul 2>&1']);
DeviceProcessEvents
| where ProcessCommandLine has_any (ShadowCopyDeletion)
| project Timestamp, DeviceName, DeviceId, ProcessCommandLine, ReportId
```

### [+] Microsoft Sentinel KQL
```
let ShadowCopyDeletion = dynamic([@'vssadmin.exe delete shadows /all /quiet', 
@'wmic.exe shadowcopy delete', @'wbadmin delete catalog -quiet', 
@'Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}',
@'del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk', 
@'wbadmin delete systemstatebackup -keepVersions:0', 
@'schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable', 
@'schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /enable >nul 2>&1', 
@'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f', 
@'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /f >nul 2>&1']);
DeviceProcessEvents
| where ProcessCommandLine has_any (ShadowCopyDeletion)
| project TimeGenerated, DeviceName, DeviceId, ProcessCommandLine, ReportId
```
:exclamation: *You MAY need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This rule detects potential attempts to delete shadow copies, which are backups of data and configurations that can be used for recovery purposes. Such attempts could be made by an attacker in an attempt to erase evidence of their activities on the device.
When this is deleted, the device or server can't recover back to the previous backup. Very critical to triage this event.

### [+] Recommended Actions
1. Investigate the process command line and the device associated with the alert to determine if the shadow copy deletion was a legitimate action or a malicious one.
2. If it is determined that the deletion was malicious, initiate an incident response plan and take appropriate steps to isolate and contain the device and any potentially affected systems.
3. Review and update existing security controls to prevent similar incidents from occurring in the future.

### [+] Resources
- [What is ShadowCopy?](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
