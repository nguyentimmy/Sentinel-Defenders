# Accounts Password that Never Expires

### [+] Defender for Endpoint
```
IdentityDirectoryEvents
| where ActionType == "Account Password Never Expires changed"
| where isnotempty(AccountName)
| extend Account = strcat(AccountDomain, "\\", AccountName)
| project Timestamp, Account, AccountDisplayName, AccountDomain, DeviceName, ReportId
```

### [+] Sentinel
```
IdentityDirectoryEvents
| where ActionType == "Account Password Never Expires changed"
| where isnotempty(AccountName)
| extend Account = strcat(AccountDomain, "\\", AccountName)
| project TimeGenerated, Account, AccountDisplayName, AccountDomain, DeviceName, ReportId
```
:exclamation: *You MAY need to turn on **Microsoft 365 Defender** or **Microsoft Defender for Endpoint** Data connector on Sentinel in order for this KQL to work.*

### [+] Description 
This alert triggers when an event is detected in the Identity Directory indicating a change to an account's password policy to never expire, and includes relevant details such as the timestamp, account name, display name, domain, device name, and report ID.

### [+] Recommended Actions
1. Reset the account password and enforcing password expiration policies

### [+] Resources
- [Why should you enforce password expiration?](https://www.n-able.com/blog/why-password-expiration-policies-matter#:~:text=The%20longer%20and%20more%20complicated,an%20organization's%20broader%20cybersecurity%20goals)
