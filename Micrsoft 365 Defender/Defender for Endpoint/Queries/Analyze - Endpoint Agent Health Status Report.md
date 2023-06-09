# Analyze: Endpoint Agent Health Status Report

### [+] Defender for Endpoint KQL
```
 let configurationIDs = dynamic([
        "scid-2000", 
        "scid-2001", 
        "scid-5001", 
        "scid-6001", 
        "scid-2002", 
        "scid-5002", 
        "scid-6002", 
        "scid-2003", 
        "scid-5092", 
        "scid-2010", 
        "scid-2011", 
        "scid-5095", 
        "scid-6095", 
        "scid-2012", 
        "scid-5090", 
        "scid-6090", 
        "scid-91",
        "scid-2013", 
        "scid-5091", 
        "scid-6091", 
        "scid-2014", 
        "scid-2016", 
        "scid-5094", 
        "scid-6094"
    ]);
    DeviceTvmSecureConfigurationAssessment
    | where ConfigurationId in (configurationIDs)
    | extend Test = case(
        ConfigurationId == "scid-2000", "SensorEnabled",
        ConfigurationId == "scid-2001", "SensorDataCollectionWin", //windows
        ConfigurationId == "scid-5001", "SensorDataCollectionMac", //macOS
        ConfigurationId == "scid-6001", "SensorDataCollectionLin", //linux
        ConfigurationId == "scid-2002", "ImpairedCommunicationsWin", //windows
        ConfigurationId == "scid-5002", "ImpairedCommunicationsMac", //macOS
        ConfigurationId == "scid-6002", "ImpairedCommunicationsLin", //linux
        ConfigurationId == "scid-2003", "TamperProtectionWin", //windows
        ConfigurationId == "scid-5092", "TamperProtectionMac", //macOS
        ConfigurationId == "scid-2010", "AntivirusEnabled",
        ConfigurationId == "scid-2011", "AntivirusSignatureVersionWin", //windows
        ConfigurationId == "scid-5095", "AntivirusSignatureVersionMac", //macOS
        ConfigurationId == "scid-6095", "AntivirusSignatureVersionLin", //linux
        ConfigurationId == "scid-2012", "RealtimeProtectionWin", //windows
        ConfigurationId == "scid-5090", "RealtimeProtectionMac", //macOS
        ConfigurationId == "scid-6090", "RealtimeProtectionLin", //linux
        ConfigurationId == "scid-91"  , "BehaviorMonitoring",
        ConfigurationId == "scid-2013", "PUAProtectionWin", // windows
        ConfigurationId == "scid-5091", "PUAProtectionMac", //macOS
        ConfigurationId == "scid-6091", "PUAProtectionLin", //linux
        ConfigurationId == "scid-2014", "AntivirusReporting",
        ConfigurationId == "scid-2016", "CloudProtectionWin", //windows
        ConfigurationId == "scid-5094", "CloudProtectionMac", //macOS
        ConfigurationId == "scid-6094", "CloudProtectionLin", //linux
        "N/A"),
        Result = case(IsApplicable == 0, "N/A", IsCompliant == 1, "GOOD", "BAD")
    | extend packed = pack(Test, Result)
    | summarize Tests = make_bag(packed), DeviceName = any(DeviceName) by DeviceId, OSPlatform
    | evaluate bag_unpack(Tests)
    | extend CloudProtection = case(
        OSPlatform has "Windows", CloudProtectionWin,
        OSPlatform has "macOS",   CloudProtectionMac,
        OSPlatform has "Linux",   CloudProtectionLin,
        "NULL")
    | extend PUAProtection = case(
        OSPlatform has "Windows", PUAProtectionWin,
        OSPlatform has "macOS",   PUAProtectionMac,
        OSPlatform has "Linux",   PUAProtectionLin,
        "NULL")
    | extend TamperProtection = case(
        OSPlatform has "Windows", TamperProtectionWin,
        OSPlatform has "macOS",   TamperProtectionMac,
        //OSPlatform has "Linux",   TamperProtectionLin,
        "NULL")
    | extend SensorDataCollection = case(
        OSPlatform has "Windows", SensorDataCollectionWin,
        OSPlatform has "macOS",   SensorDataCollectionMac,
        OSPlatform has "Linux",   SensorDataCollectionLin,
        "NULL")
    | extend ImpairedCommunications = case(
        OSPlatform has "Windows", ImpairedCommunicationsWin,
        OSPlatform has "macOS",   ImpairedCommunicationsMac,
        OSPlatform has "Linux",   ImpairedCommunicationsLin,
        "NULL")
    | extend RealtimeProtection = case(
        OSPlatform has "Windows", RealtimeProtectionWin,
        OSPlatform has "macOS",   RealtimeProtectionMac,
        OSPlatform has "Linux",   RealtimeProtectionLin,
        "NULL")
    | extend AntivirusSignatureVersion = case(
        OSPlatform has "Windows", AntivirusSignatureVersionWin,
        OSPlatform has "macOS",   AntivirusSignatureVersionMac,
        OSPlatform has "Linux",   AntivirusSignatureVersionLin,
        "NULL")
    | project-away *Win, *Mac, *Lin

```

### [+] Microsoft Sentinel KQL
```
Not available yet.
```

### [+] Description 
This query provides a report of many of the best practice configurations for Microsoft Defender ATP deployment. It checks if the configuration is in line with the recommended settings for various capabilities, such as Antivirus, Tamper Protection, PUA Protection, Cloud Protection, and more. The results are divided into GOOD, BAD, and N/A (if the capability is not applicable). The query also includes a mapping of the different configurations to the OS platform (Windows, macOS, or Linux) and lists the configuration status for each platform. 

### [+] Resources 
- Forked from [Microsoft Offical Github Repo](https://github.com/Azure/Azure-Sentinel/blob/master/Hunting%20Queries/Microsoft%20365%20Defender/General%20queries/Endpoint%20Agent%20Health%20Status%20Report.yaml)
