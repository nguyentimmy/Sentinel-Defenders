# Random Space - space for ideas, rough draft, thoughts, and plans 

### Blogs and Resources
- https://stefanpems.github.io/M365D-raw-data-ingestion-in-Sentinel/

### KQL's Rough Draft
```
//
SecurityAlert
| where TimeGenerated > ago (7d)
| where ProviderName == "OATP"
| where AlertName contains "email"
| summarize count() by AlertName
| render columnchart 
```
