# Sentinel Checklist 

### 1. Workspace setup
- [ ] **Task 1:** Create a dedicated Log Analytics workspace for Sentinel to ingest data and logs.
     - [ ] How many workspaces are you going manage? 
        - Ideally one workspace is recommended for a more centralized management and easier administration. 
        - Provides better streamlined ingestions, don't have to worry about managing data connectors and API on multiple workspaces.
        - Improves query performance since all data is in one place. 
        - Cost effective by consolidating data such as security policies, analytics rules, and other Sentinel components will be all in one workspace.
  
- [ ] **Task 2:** Ensure proper access control by granting appropriate permissions to users and groups.
  - [ ]   Which teams or roles will have the appropriate RBAC?

### 2. Data connectors and Log Ingestions 
- [ ] **Task 1:**  Enable relevant data connectors to ingest logs from various sources like Azure services, Microsoft 365, and third-party security products.
     - [ ] How are workstation and server logs getting forwarded?
          - Is it all getting logged through a centralized forwader to a SIEM?
               - Third Party Log Management
               - Native Forwarder (Windows Event Forwarder for Windows, Syslogs for Mac)
               - EDR / XDR agents
          - Is it all getting logged through an EDR 
     - [ ] What data is getting ingested?
          - Ingest data that is relevant to the environment. 
          - What are the other mission critical assets to monitor? 
          

     - [ ] Ensure that required agents (such as Microsoft Monitoring Agent or Azure Log Analytics agent) are installed and configured on the relevant devices.
