# Phishing and Junk Overview

### [+] Sentinel 
```
SecurityAlert
| where AlertName contains "Email reported by user as junk" or 
        AlertName contains "Email reported by user as malware or phish" or
        AlertName contains "A potentially malicious URL click was detected" or
        AlertName contains "Phishing email detected at the time of delivery" // This alert needs to be configured in Compliance Portal on the Policies tab
| summarize count() by AlertName
| render piechart
```
:exclamation: *This chart will NOT work on Defender for Endpoint advanced hunt. Will need to turn on M365 Defender data connectors in order to ingest data.*

### [+] Description 
This visualization retrieves security alerts related to potentially malicious activities in email and URLs, including junk emails, malware or phish emails, potentially malicious URL clicks, and phishing emails detected at the time of delivery. The query filters alerts based on their names and returns a count of each type of alert. This information can be useful in identifying potential threats and taking proactive measures to mitigate them. 

### [+] Thoughts
❗ Phishing attacks are one of the most dangerous types of cyber attacks as they prey on human error and exploit human vulnerabilities rather than technical vulnerabilities. These attacks use social engineering techniques to trick individuals into divulging sensitive information, downloading malware, or performing some other action that can compromise security. Phishing attacks are often successful because they are difficult to detect, and they can result in significant financial loss, reputational damage, and even legal consequences. It is essential to educate individuals about the risks of phishing and to implement strong security measures to prevent these attacks from succeeding.

### [+] Recommended Actions
1. It is crucial to immediately investigate any alerts triggered when a user clicks on a potentially malicious link. Failure to take prompt action could result in serious security breaches and compromise the entire network.

### [+] Resources
- [Why is phishing so dangerous?](https://www.techradar.com/news/what-is-phishing-and-how-dangerous-is-it)


