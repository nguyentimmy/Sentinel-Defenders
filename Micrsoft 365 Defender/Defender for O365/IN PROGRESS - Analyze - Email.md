# In Progress
```
// Email events from the past 24 hours where the emails were delivered to the inbox and were classified as spam or phish
EmailEvents
| where Timestamp > ago(1d)
| where DeliveryAction contains "Delivered" and DeliveryLocation contains "Inbox" and ThreatTypes in ('Spam', 'Phish')
| summarize count() by DeliveryLocation, DeliveryAction, ThreatTypes
```

```
UrlClickEvents
| where ActionType == "ClickBlocked"
| project Timestamp, Url, Workload, AccountUpn, ThreatTypes, IsClickedThrough
| sort by Timestamp
```

```
let ExecutableFileExtentions = dynamic(['bat', 'cmd', 'com', 'cpl', 'dll', 'ex', 'exe', 'jse', 'lnk','msc', 'ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf']);
EmailEvents
// Only display inbound emails
| where EmailDirection == 'Inbound'
// Join the email events with the attachment information, that the email must have an attachment.
| join kind=inner EmailAttachmentInfo on NetworkMessageId
// extract the file extension from the filename
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
| where isnotempty(FileExtension)
// Filter on executable file extensions
| where FileExtension in~ (ExecutableFileExtentions)
| summarize ['Target Mailboxes'] = make_set(RecipientEmailAddress), ['Sender Addresses'] = make_set(SenderFromAddress), ['Email Subject'] = make_set(Subject) by SHA256, FileName
```

# Random Notes 
```
| extend 
    SPF = parse_json(AuthenticationDetails).SPF,
    DMARC  = parse_json(AuthenticationDetails).DMARC
 ``` 
   ![https://github.com/nguyentimmy/msft-security-stack/blob/main/Resources/Pictures/SPF%20JSON.PNG](https://github.com/nguyentimmy/msft-security-stack/blob/main/Resources/Pictures/SPF%20JSON.PNG)
