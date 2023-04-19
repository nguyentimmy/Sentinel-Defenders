=# ASR Triggered By Potential Ransomware 

### [+] Defender for Endpoint & Microsoft Sentinel KQL
```
// Finds a pontential block on a ransomware.

DeviceEvents
| where ActionType contains 'AsrRansomwareBlocked'
| extend RuleId = extract("AsrRuleId\\[(.*?)\\]", 1, AdditionalFields)
| extend RuleName = extract("AsrRuleName\\[(.*?)\\]", 1, AdditionalFields)
| project Timestamp, DeviceName, ActionType, RuleId, RuleName, FileName, InitiatingProcessCommandLine, RemoteUrl
| order by Timestamp desc
```
:exclamation: *You will need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
ASR blocks related to ransomware in your environment.

### [+] Defender for Endpoint & Microsoft Sentinel KQL
1. Investigate the ASR blocks triggered by this query to determine the scope and impact of any potential ransomware attacks.
2. Follow Playbook:

- 1️⃣: Notify User: Notify the user that they clicked on a potentially malicious link and instruct them to immediately disconnect from the network or Wi-Fi, if possible. Advise them to avoid accessing any sensitive data until further notice.
- 2️⃣: Notify Manager: Notify the manager of the user and provide a brief explanation of the situation. This should include any potential impact on the business and the user's work.
- 3️⃣: Isolate or Disconnect: If possible, isolate or disconnect the affected device from the network or Wi-Fi. This can help prevent the spread of any malware or viruses that may have been downloaded. Isolating is the prefer method, you can conduct further forensics and analysis on the device.
- 4️⃣: Send Password Reset Link: Send the user a password reset link to ensure their account is secure. Advise the user to follow the instructions in the password reset email and create a new, strong password.
- 5️⃣: Scan for Malware: Run a malware scan on the affected device to check for any signs of malware or viruses that may have been downloaded.
- 6️⃣: Clean and Reconnect: Once the malware scan is complete and no threats are found, clean and reconnect the device to the network or Wi-Fi.
- ❗: If malware is detected, the affected device must be immediately isolated and the end user notified. A new device should be provided to the user after reimaging the device. The incident must also be escalated to the Incident Response team.
