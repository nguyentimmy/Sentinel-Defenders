# TOR Connection Established

### [+] Defender for Endpoint
```
// README! A custom detection rule may NOT be needed since MDE already have this built in
DeviceNetworkEvents 
| where Timestamp > ago(1d)
| where RemoteUrl has "torrent" or RemoteUrl has "vuze" or RemoteUrl has "azureus" or RemoteUrl endswith ".tor" or InitiatingProcessFileName has "torrent" or InitiatingProcessFileName has "vuze" or InitiatingProcessFileName contains "azureus" 
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, RemoteUrl , RemoteIP , RemotePort, ReportId


```

### [+] Sentinel KQL
```
DeviceNetworkEvents 
| where TimeGenerated > ago(1d)
| where RemoteUrl has "torrent" or RemoteUrl has "vuze" or RemoteUrl has "azureus" or RemoteUrl endswith ".tor" or InitiatingProcessFileName has "torrent" or InitiatingProcessFileName has "vuze" or InitiatingProcessFileName contains "azureus" 
| project TimeGenerated, DeviceName, DeviceId, InitiatingProcessFileName, RemoteUrl , RemoteIP , RemotePort, ReportId
```

### [+] Description 
This alert is triggered when a device on the network is observed communicating with a TOR network, or attempting to access a TOR-related URL. TOR networks are often used by threat actors to obfuscate their location and activity, and therefore, TOR network activity can indicate a potential security threat.

### [+] Recommended Actions

1. Investigate the affected device(s) for any unauthorized or suspicious activity and determine the scope of the potential threat.
2. Quarantine the affected device(s) to prevent further spread of any malware or unauthorized software if needed.
3. Conduct a thorough review of the organization's policies and procedures regarding the use of torrenting software and browsing of torrent-related websites, and consider implementing more stringent controls if necessary.

### [+] Resources 
- [Why is Tor a security risk?](https://hackcur.io/onion-and-on-and-on-hacking-the-internet-with-tor/#:~:text=This%20grants%20Tor%20users%20extremely,content%20restrictions%20and%20state%20censorship.)
