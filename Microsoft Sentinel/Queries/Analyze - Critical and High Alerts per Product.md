# Critical and High Alerts per Product
### [+] Sentinel 
```
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize
    ['Total Alert Count']=count(),
    ['Total High or Critical Count']=countif(AlertSeverity in ("Critical", "High"))
    by ProductName
| extend Percentage=(todouble(['Total High or Critical Count']) * 100 / todouble(['Total Alert Count']))
| project-reorder ProductName, ['Total Alert Count'], ['Total High or Critical Count'], Percentage
| sort by Percentage desc 
```
### [+] Description 
Calculates the total number of alerts and the total number of alerts with either "Critical" or "High" severity levels, and calculates the percentage of high or critical alerts. 

### [+] Resources 
- Forked directly from [@Reprise99](https://hackcur.io/onion-and-on-and-on-hacking-the-internet-with-tor/#:~:text=This%20grants%20Tor%20users%20extremely,content%20restrictions%20and%20state%20censorship.) please give him credit and a follow!
