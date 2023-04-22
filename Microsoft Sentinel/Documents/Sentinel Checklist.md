# Sentinel Checklist 

### 1. Workspace setup
- [ ] **Task 1:** Create a dedicated Log Analytics workspace for Sentinel to ingest data and logs.
     - [ ] How many workspaces are you going manage? 
        - Ideally one workspace is recommended for a more centralized management and easier administration. 
        - Provides better streamlined ingestions, don't have to worry about multiple data connectors and API. 
        - Improves query performance since all data is in one place. 
        - Cost effective by consolidating data. Security policies, analytics rules, and other Sentinel components will be all in one workspace,
  
- [ ] **Task 2:** Ensure proper access control by granting appropriate permissions to users and groups.
  - [ ]   Which teams or roles will have the appropriate RBAC?
