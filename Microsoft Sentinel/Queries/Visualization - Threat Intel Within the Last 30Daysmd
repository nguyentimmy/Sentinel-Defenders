#  Threat Intel Within the Last 30Days

### [+] Sentinel 
```
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| extend IOC = iff(isnotempty(DomainName), DomainName, iff(isnotempty(NetworkIP), NetworkIP, iff(isnotempty(Url),Url, "No IOC defined")))
| summarize count() by IOC
| render piechart with (title="IOC last month")
```
### [+] Description 
This visual searches for Threat Intelligence Indicators that have been generated in the last 30 days, and then extends the search by creating an Indicator of Compromise (IOC) for each Threat Intelligence Indicator found.

### [+] Resources
- Forked from directly from [@Bert-JanP](https://github.com/Bert-JanP), with a few modifications, please give him credit and a follow!

