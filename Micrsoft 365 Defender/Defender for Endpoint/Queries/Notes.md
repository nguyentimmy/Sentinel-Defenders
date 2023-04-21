# Just Random Notes

### Trying to create a regex kql to query for URLs in a link, still in progress.
```
let URL = externaldata(RemoteUrl: string)[@"https://github.com/nguyentimmy/msft-security-stack/blob/main/M365%20Defender/Defender%20for%20Endpoint/Threat%20Hunting/hosts.txt"] with (format="txt", ignoreFirstRecord=True);
let DomainPattern = @"(^|\b)(https?://)?([a-z0-9]+\.)*\.com(/[^\s]*)?($|\b)";
let TimeFrame = 7d;
let URL = materialize (
     ThreatIntelFeed
     | where RemoteUrl matches regex DomainPattern 
     | distinct RemoteUrl
);
DeviceNetworkEvents
| where RemoteUrl in (URL)
| where RemoteUrl matches regex DomainPattern
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine
```
