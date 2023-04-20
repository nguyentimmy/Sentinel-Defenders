# Potential Bloodhound Activity Detected on Device 

### [+] Defender for Endpoint
```
// Query for any bloodhound related processes and files
let BloodhoundCLI = dynamic([ 'Import-Module Sharphound.ps1' , '-collectionMethod', 'invoke-bloodhound', 'get-bloodhounddata']);
let BloodhoundExe = dynamic(['SharpHound.exe', 'BloodHound.exe', 'Neo4j-Management.exe']);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any(BloodhoundCLI) or ProcessCommandLine has_any(BloodhoundExe) or FileName has_any(BloodhoundExe)
| project Timestamp, DeviceName, AccountName, AccountDomain, ProcessCommandLine, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName
```

### [+] Sentinel
```
// Query for process events containing known BloodHound commands
let BloodhoundCommands = dynamic(['-collectionMethod', 'invoke-bloodhound', 'get-bloodhounddata']);
let BloodhoundExe = dynamic(['SharpHound.exe', 'BloodHound.exe', 'Neo4j-Management.exe']);
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where ProcessCommandLine has_any(BloodhoundCommands) and ProcessCommandLine has_any(BloodhoundExe)
| project TimeGenerated, DeviceName, AccountName, AccountDomain, ProcessCommandLine, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName
```
:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This alert is generated when Bloodhound-related processes or files are detected on a device in the environment. Bloodhound is a popular tool used in Active Directory environments to gather information about user and computer accounts, group memberships, and other AD objects to identify potential attack paths. Attackers can use Bloodhound to move laterally within the network and escalate privileges, making it a potential threat to the organization's security.

### [+] Recommended Actions
1. Investigate the device where the Bloodhound-related activity was detected to determine the scope and severity of the potential threat.
2. Identify the root cause of the Bloodhound-related activity and take appropriate actions to remediate the issue.
3. Review the user and computer accounts, group memberships, and other AD objects accessed by the detected Bloodhound-related activity to ensure that they have not been compromised or misused.
4. Check for any lateral movement or privilege escalation that may have been attempted using Bloodhound and take appropriate actions to prevent further damage.
5. If necessary, isolate the affected device from the network to prevent further potential harm.

### [+] Resources
- [What is BloodHound?](https://attack.mitre.org/software/S0521/)
