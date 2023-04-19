# Attack Side Reduction (ASR)

### [+] What is ASR?
Attack surfaces are all the places where your organization is vulnerable to cyberthreats and attacks. Defender for Endpoint includes several capabilities to help reduce your attack surfaces. 

Your organization's attack surface includes all the places where an attacker could compromise your organization's devices or networks. Reducing your attack surface means protecting your organization's devices and network, which leaves attackers with fewer ways to perform attacks. Configuring attack surface reduction rules in Microsoft Defender for Endpoint can help! 

Attack surface reduction rules target certain software behaviors, such as:
- Launching executable files and scripts that attempt to download or run files
- Running obfuscated or otherwise suspicious scripts
- Performing behaviors that apps don't usually initiate during normal day-to-day work

### [+] ASR Core Components 
- AsrRuleBlocked -  Indicates that the ASR rule was triggered, and the potentially malicious activity was blocked.
- AsrRuleAudit - Action type indicates that the ASR rule was triggered, and the event was logged for auditing purposes, but the action was not blocked. 
- AsrRuleEnforced -  Action type indicates that the ASR rule was enforced, and the potentially malicious activity was prevented.

### [+] Resources
[Overview of ASR](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide)
[How to configure ASR](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide)
