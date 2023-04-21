
```
// Email events from the past 24 hours where the emails were delivered to the inbox and were classified as spam or phish
EmailEvents
| where Timestamp > ago(1d)
| where DeliveryAction contains "Delivered" and DeliveryLocation contains "Inbox" and ThreatTypes in ('Spam', 'Phish')
| summarize count() by DeliveryLocation, DeliveryAction, ThreatTypes
```
