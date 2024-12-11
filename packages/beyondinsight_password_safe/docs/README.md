# BeyondInsight integration

BeyondInsight enables real-time monitoring of privileged account access, session recordings, and password checkout patterns to help security teams maintain compliance and quickly identify potential privilege abuse.


## Data streams

- **`useraudit`** Provides audit data for users that includes user actions like login, logout, pwd change etc on a machine
This data stream utilizes the BeyondInsight API's `/v3/UserAudits` endpoint.

- **`session`** Provides details on active sessions and its status with duration for an asset. 
This data stream utilizes the BeyondInsight API's `/v3/Sessions` endpoint.

- **`managedsystem`** Provides a list of managed systems.  
This data stream utilizes the BeyondInsight API's `/v3//ManagedSystems` endpoint.

- **`managedaccount`** Provides a list of managed accounts.  
This data stream utilizes the BeyondInsight API's `/v3//ManagedAccounts` endpoint.

## Requirements

### API Key based authentication
All the connectors utilizes API key from Beyondtrust and use it with SignAppIn endpoint passing the key as authorization header.
The API key is a cryptographically strong random sequence of numbers hashed into a 128-character string. It is encrypted and stored
internally using AES 256 encryption. Any language with a Representational State Transfer (REST) compliant interface can access the API
with the API key and RunAs in the authorization header.

**Authorization header**
Use the web request authorization header to communicate the API application key, the RunAs username, and the user password:

**key**: The API key configured in BeyondInsight for your application.

**runas**: The username of a BeyondInsight user that has been granted permission to use the API key.

**pwd**: The RunAs user password surrounded by square brackets (optional; required only if the User Password is required on the
application API registration).

Authorization=PS-Auth key=c479a66f…c9484d; runas=doe-main\johndoe; pwd=[un1qu3];

## Setup

### Step 1: Create an Application in BeyondTrust:

To create a connection to BeyondInsight, an [application must be created](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) first. Credentials generated during this process are required for the subsequent steps.

**BeyondInsight API Credentials**  
- **`client_id`** is an app specific ID generated during app creation, and is available in the app settings.
- **`client_secret`** is only available once after app creation. Can be regenerated if lost.

Permissions can be set up on app creation or can be updated for existing app

### Step 2: Integration Setup:

To set up the inventory data stream these three fields are required:
- `api_host` (the BeyondTrust host)
- `client_id`
- `client_secret`



## Logs

### UserAudit

UserAudit documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.useraudit"`.

Here is an example useraudit document:

An example event for `useraudit` looks as following:

```json
{
        "_index": ".ds-logs-beyondinsight_password_safe.useraudit-default-2024.12.11-000001",
        "_id": "LBcj7DNTqMFRXobggSHJ376m2kk=",
        "_score": 1,
        "_ignored": [
          "beyondinsight_password_safe.useraudit.ipaddress"
        ],
        "_source": {
          "input": {
            "type": "cel"
          },
          "agent": {
            "name": "docker-fleet-agent",
            "id": "ac818783-65d7-449f-9d6e-92870ed35c5c",
            "type": "filebeat",
            "ephemeral_id": "7d367dd3-1b77-441e-83bb-d015782c1bc5",
            "version": "8.12.2"
          },
          "beyondinsight_password_safe": {
            "useraudit": {
              "ipaddress": "223.233.080.172",
              "audit_id": 22182,
              "action_type": "Login",
              "user_id": 6,
              "user_name": "balaji_dongare@epam.com",
              "section": "PMM API SignAppIn",
              "create_date": "2024-12-11T11:31:55.107Z"
            }
          },
          "@timestamp": "2024-12-11T11:31:55.107Z",
          "ecs": {
            "version": "8.11.0"
          },
          "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "beyondinsight_password_safe.useraudit"
          },
          "elastic_agent": {
            "id": "ac818783-65d7-449f-9d6e-92870ed35c5c",
            "version": "8.12.2",
            "snapshot": false
          },
          "host": {
            "hostname": "docker-fleet-agent",
            "os": {
              "kernel": "6.6.51-0-virt",
              "codename": "focal",
              "name": "Ubuntu",
              "type": "linux",
              "family": "debian",
              "version": "20.04.6 LTS (Focal Fossa)",
              "platform": "ubuntu"
            },
            "ip": [
              "172.24.0.7"
            ],
            "containerized": false,
            "name": "docker-fleet-agent",
            "id": "29b44b57f32c4ff282841a8a4406ef95",
            "mac": [
              "02-42-AC-18-00-07"
            ],
            "architecture": "aarch64"
          },
          "event": {
            "agent_id_status": "verified",
            "ingested": "2024-12-11T11:32:00Z",
            "kind": "event",
            "module": "beyondinsight_password_safe",
            "id": "22182",
            "category": [
              "iam"
            ],
            "type": [
              "info"
            ],
            "dataset": "beyondinsight_password_safe.useraudit"
          },
          "user": {
            "name": "balaji_dongare@epam.com",
            "id": "6"
          }
        }
      }
 
```

The following non-ECS fields are used in useraudit documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |
| beyondinsight_password_safe.useraudit.audit_id |  | keyword |
| beyondinsight_password_safe.useraudit.action_type |  | keyword |
| beyondinsight_password_safe.useraudit.section |  | boolean |
| beyondinsight_password_safe.useraudit.user_id |  | integer |
| beyondinsight_password_safe.useraudit.user_name |  | keyword |
| beyondinsight_password_safe.useraudit.ipaddress |  | ip |
| beyondinsight_password_safe.useraudit.create_date |  | date |



### Session

UserAudit documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.session"`.

Here is an example session document:

An example event for `session` looks as following:

```json
{
        "_index": ".ds-logs-beyondinsight_password_safe.session-default-2024.12.11-000004",
        "_id": "RfP2MMIFCS+8Zi9m137F6dJpO9k=",
        "_score": null,
        "_source": {
          "input": {
            "type": "cel"
          },
          "agent": {
            "name": "docker-fleet-agent",
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "ephemeral_id": "4394976e-aa96-433d-9872-979278c1dfcf",
            "type": "filebeat",
            "version": "8.12.2"
          },
          "beyondinsight_password_safe": {
            "session": {
              "duration": 0,
              "protocol": "rdp",
              "record_key": "892067f27037140e5d009db50031b15d4ca224376504c13b1695f19c4d01991a",
              "archive_status": "not_archived",
              "asset_name": "123.6.7.8.8",
              "user_id": "2",
              "session_id": "3",
              "managed_account_name": """sdfsf\sdfsdfs""",
              "status": "not_started",
              "node_id": "a5c29153-b351-41f1-a12b-0c4da9408d79"
            }
          },
          "@timestamp": "2024-12-11T12:24:24.757Z",
          "ecs": {
            "version": "8.11.0"
          },
          "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "beyondinsight_password_safe.session"
          },
          "host": {
            "hostname": "docker-fleet-agent",
            "os": {
              "kernel": "5.15.167.4-microsoft-standard-WSL2",
              "codename": "focal",
              "name": "Ubuntu",
              "family": "debian",
              "type": "linux",
              "version": "20.04.6 LTS (Focal Fossa)",
              "platform": "ubuntu"
            },
            "containerized": true,
            "ip": [
              "172.18.0.7"
            ],
            "name": "docker-fleet-agent",
            "id": "009f8d5d825944429c9ae8d252b0019a",
            "mac": [
              "02-42-AC-12-00-07"
            ],
            "architecture": "x86_64"
          },
          "elastic_agent": {
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "version": "8.12.2",
            "snapshot": false
          },
          "event": {
            "duration": 0,
            "agent_id_status": "verified",
            "ingested": "2024-12-11T12:24:25Z",
            "kind": "event",
            "module": "beyondinsight_password_safe",
            "id": "3",
            "category": [
              "session"
            ],
            "type": [
              "info"
            ],
            "dataset": "beyondinsight_password_safe.session"
          }
        },
        "sort": [
          1733919864757
        ]
      }
 
```

The following non-ECS fields are used in session documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |
| beyondinsight_password_safe.useraudit.audit_id |  | keyword |
| beyondinsight_password_safe.useraudit.action_type |  | keyword |
| beyondinsight_password_safe.useraudit.section |  | boolean |
| beyondinsight_password_safe.useraudit.user_id |  | integer |
| beyondinsight_password_safe.useraudit.user_name |  | keyword |
| beyondinsight_password_safe.useraudit.ipaddress |  | ip |
| beyondinsight_password_safe.useraudit.create_date |  | date |

### ManagedSystem

ManagedSystem documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.managedsystem"`.

Here is an example managedsystem document:

An example event for `managedsystem` looks as following:

```json
{
        "_index": ".ds-logs-beyondinsight_password_safe.managedsystem-default-2024.12.11-000003",
        "_id": "W+7DCDPfDZqFu+hJXnXjPOvAhfg=",
        "_score": null,
        "_source": {
          "input": {
            "type": "cel"
          },
          "agent": {
            "name": "docker-fleet-agent",
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "type": "filebeat",
            "ephemeral_id": "4394976e-aa96-433d-9872-979278c1dfcf",
            "version": "8.12.2"
          },
          "beyondinsight_password_safe": {
            "managedsystem": {
              "ipaddress": "85.206.176.106",
              "remote_client_type": "None",
              "description": "test",
              "dsskey_rule_id": 0,
              "entity_type_id": 1,
              "timeout": 30,
              "change_frequency_type": "first",
              "managed_system_id": 2,
              "is_application_host": false,
              "workgroup_id": 1,
              "max_release_duration": 10079,
              "change_time": "23:30",
              "check_password_flag": false,
              "system_name": "windows",
              "password_rule_id": 0,
              "change_password_after_any_release_flag": false,
              "dns_name": "test",
              "functional_account_id": 4,
              "reset_password_on_mismatch_flag": false,
              "account_name_format": 0,
              "port": 22,
              "platform_id": 46,
              "release_duration": 120,
              "isarelease_duration": 120,
              "change_frequency_days": 30,
              "host_name": "windows",
              "auto_management_flag": true
            }
          },
          "@timestamp": "2024-12-11T12:24:54.103Z",
          "ecs": {
            "version": "8.11.0"
          },
          "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "beyondinsight_password_safe.managedsystem"
          },
          "elastic_agent": {
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "version": "8.12.2",
            "snapshot": false
          },
          "host": {
            "hostname": "docker-fleet-agent",
            "os": {
              "kernel": "5.15.167.4-microsoft-standard-WSL2",
              "codename": "focal",
              "name": "Ubuntu",
              "type": "linux",
              "family": "debian",
              "version": "20.04.6 LTS (Focal Fossa)",
              "platform": "ubuntu"
            },
            "containerized": true,
            "ip": [
              "172.18.0.7"
            ],
            "name": "docker-fleet-agent",
            "id": "009f8d5d825944429c9ae8d252b0019a",
            "mac": [
              "02-42-AC-12-00-07"
            ],
            "architecture": "x86_64"
          },
          "event": {
            "agent_id_status": "verified",
            "ingested": "2024-12-11T12:24:55Z",
            "kind": "asset",
            "module": "beyondinsight_password_safe",
            "category": [
              "iam"
            ],
            "type": [
              "info"
            ],
            "dataset": "beyondinsight_password_safe.managedsystem"
          }
        },
        "sort": [
          1733919894103
        ]
      }
 
```

The following non-ECS fields are used in managedsystem documents:

**Exported fields**

| Field | Target Field | Type |
|---|---|---|
|@timestamp (ECS field)|date
beyondinsight_password_safe.managedsystem|Data_stream.dataset (ECS field)|Constand_keyword
default|data_stream.namespace (ECS field)|constant_keyword
logs|data_stream.type (ECS field)|constant_keyword
“managedsystem”|tags (ECS field)|constant_keyword
cel|input.type (ECS field)|keyword
beyondinsight_password_safe.managedsystem.TotalCount|beyondinsight_password_safe.managedsystem.total_count|integer
beyondinsight_password_safe.managedsystem.Data|beyondinsight_password_safe.managedsystem.data|nested
beyondinsight_password_safe.managedsystem.Data.WorkgroupID|beyondinsight_password_safe.managedsystem.data.workgroup_id|integer
beyondinsight_password_safe.managedsystem.Data.HostName|beyondinsight_password_safe.managedsystem.data.host_name|keyword
beyondinsight_password_safe.managedsystem.Data.IPAddress|beyondinsight_password_safe.managedsystem.data.ipaddress|ip
beyondinsight_password_safe.managedsystem.Data.DNSName|beyondinsight_password_safe.managedsystem.data.dns_name|keyword
beyondinsight_password_safe.managedsystem.Data.InstanceName|beyondinsight_password_safe.managedsystem.data.instance_name|keyword
beyondinsight_password_safe.managedsystem.Data.IsDefalutInstance|beyondinsight_password_safe.managedsystem.data.is_default_instance|bool
beyondinsight_password_safe.managedsystem.Data.Template|beyondinsight_password_safe.managedsystem.data.template|keyword
beyondinsight_password_safe.managedsystem.Data.ForestName|beyondinsight_password_safe.managedsystem.data.forest_name|keyword
beyondinsight_password_safe.managedsystem.Data.UseSSL|beyondinsight_password_safe.managedsystem.data.use_ssl|bool
beyondinsight_password_safe.managedsystem.Data.ManagedSystemID|beyondinsight_password_safe.managedsystem.data.managed_system_id|integer
beyondinsight_password_safe.managedsystem.Data.EntityTypeID|beyondinsight_password_safe.managedsystem.data.entity_type_id|integer
beyondinsight_password_safe.managedsystem.Data.AssetID|beyondinsight_password_safe.managedsystem.data.asset_id|integer
beyondinsight_password_safe.managedsystem.Data.DatabaseID|beyondinsight_password_safe.managedsystem.data.database_id|integer
beyondinsight_password_safe.managedsystem.Data.DirectoryID|beyondinsight_password_safe.managedsystem.data.directory_id|integer
beyondinsight_password_safe.managedsystem.Data.CloudID|beyondinsight_password_safe.managedsystem.data.cloud_id|integer
beyondinsight_password_safe.managedsystem.Data.SystemName|beyondinsight_password_safe.managedsystem.data.system_name|keyword
beyondinsight_password_safe.managedsystem.Data.Timeout|beyondinsight_password_safe.managedsystem.data.timeout|integer
beyondinsight_password_safe.managedsystem.Data.PlatformID|beyondinsight_password_safe.managedsystem.data.platform_id|integer
beyondinsight_password_safe.managedsystem.Data.NetBiosName|beyondinsight_password_safe.managedsystem.data.net_bios_name|keyword
beyondinsight_password_safe.managedsystem.Data.ContactEmail|beyondinsight_password_safe.managedsystem.data.contact_email|keyword
beyondinsight_password_safe.managedsystem.Data.Description|beyondinsight_password_safe.managedsystem.data.description|keyword
beyondinsight_password_safe.managedsystem.Data.Port|beyondinsight_password_safe.managedsystem.data.port|integer
beyondinsight_password_safe.managedsystem.Data.Timeout|beyondinsight_password_safe.managedsystem.data.timeout|integer
beyondinsight_password_safe.managedsystem.Data. SshKeyEnforcementMode|beyondinsight_password_safe.managedsystem.data. sshKey_enforcement_mode|integer
beyondinsight_password_safe.managedsystem.Data.PasswordRuleID|beyondinsight_password_safe.managedsystem.data.password_rule_id|integer
beyondinsight_password_safe.managedsystem.Data.DSSKeyRuleID|beyondinsight_password_safe.managedsystem.data.dss_key_rule_id|integer
beyondinsight_password_safe.managedsystem.Data.LoginAccountID|beyondinsight_password_safe.managedsystem.data.login_account_id|integer
beyondinsight_password_safe.managedsystem.Data.AccountNameFormat|beyondinsight_password_safe.managedsystem.data.account_name_format|integer
beyondinsight_password_safe.managedsystem.Data. OracleInternetDirectoryID |beyondinsight_password_safe.managedsystem.data. Oracle_Internet_Directory_id |keyword
beyondinsight_password_safe.managedsystem.Data. OracleInternetDirectoryServiceName |beyondinsight_password_safe.managedsystem.data. oracle_internet_directory_service_name |keyword
beyondinsight_password_safe.managedsystem.Data.ReleaseDuration|beyondinsight_password_safe.managedsystem.data.release_duration|integer
beyondinsight_password_safe.managedsystem.Data.MaxReleaseDuration|beyondinsight_password_safe.managedsystem.data.max_release_duration|integer
beyondinsight_password_safe.managedsystem.Data.ISAReleaseDuration |beyondinsight_password_safe.managedsystem.data.is_a_release_duration |integer
beyondinsight_password_safe.managedsystem.Data.AutoManagementFlag |beyondinsight_password_safe.managedsystem.data.auto_management_flag |bool
beyondinsight_password_safe.managedsystem.Data.FunctionalAccountID|beyondinsight_password_safe.managedsystem.data.functional_account_id |integer
beyondinsight_password_safe.managedsystem.Data.ElevationCommand|beyondinsight_password_safe.managedsystem.data.elevation_command|keyword
beyondinsight_password_safe.managedsystem.Data.CheckPasswordFlag|beyondinsight_password_safe.managedsystem.data.check_password_flag|bool
beyondinsight_password_safe.managedsystem.Data.ChangePasswordAfterAnyReleaseFlag |beyondinsight_password_safe.managedsystem.data.change_password_after_any_release_flag|bool
beyondinsight_password_safe.managedsystem.Data.ResetPasswordOnMismatchFlag |beyondinsight_password_safe.managedsystem.data.reset_password_on_mismatch_flag|bool
beyondinsight_password_safe.managedsystem.Data.ChangeFrequencyType |beyondinsight_password_safe.managedsystem.data.change_frequency_type |keyword
beyondinsight_password_safe.managedsystem.Data.ChangeFrequencyDays|beyondinsight_password_safe.managedsystem.data.change_frequency_days|integer
beyondinsight_password_safe.managedsystem.Data.ChangeTime|beyondinsight_password_safe.managedsystem.data.change_time|keyword
beyondinsight_password_safe.managedsystem.Data.RemoteClientType|beyondinsight_password_safe.managedsystem.data.remote_client_type|keyword
beyondinsight_password_safe.managedsystem.Data.ApplicationHostID|beyondinsight_password_safe.managedsystem.data.application_host_id|integer
beyondinsight_password_safe.managedsystem.Data.IsApplicationHost|beyondinsight_password_safe.managedsystem.data.is_application_host|bool
beyondinsight_password_safe.managedsystem.Data.AccessURL|beyondinsight_password_safe.managedsystem.data.access_url|keyword



### ManagedAccount

ManagedSystem documents can be found using the API model by setting the filter `event.dataset :"beyondinsight_password_safe.managedaccount"`.

Here is an example managedaccount document:

An example event for `managedaccount` looks as following:

```json
{
        "_index": ".ds-logs-beyondinsight_password_safe.managedaccount-default-2024.12.11-000001",
        "_id": "4J23rqov7peRAEhvv6gvy7hzsUA=",
        "_score": null,
        "_source": {
          "input": {
            "type": "cel"
          },
          "agent": {
            "name": "docker-fleet-agent",
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "ephemeral_id": "4394976e-aa96-433d-9872-979278c1dfcf",
            "type": "filebeat",
            "version": "8.12.2"
          },
          "beyondinsight_password_safe": {
            "managedaccount": {
              "is_isaaccess": true,
              "last_change_date": "2024-12-10T08:58:19.163Z",
              "account_id": "7",
              "is_changing": false,
              "default_release_duration": 120,
              "system_id": "7",
              "system_name": "BasketMuskOx",
              "account_name": "AsaZ.Suarez",
              "platform_id": "4",
              "preferred_node_id": "2ca45774-d4e0-4b8f-9b52-3f52b78ae2ca",
              "maximum_release_duration": 525600,
              "change_state": 0
            }
          },
          "@timestamp": "2024-12-11T12:24:27.579Z",
          "ecs": {
            "version": "8.11.0"
          },
          "data_stream": {
            "namespace": "default",
            "type": "logs",
            "dataset": "beyondinsight_password_safe.managedaccount"
          },
          "host": {
            "hostname": "docker-fleet-agent",
            "os": {
              "kernel": "5.15.167.4-microsoft-standard-WSL2",
              "codename": "focal",
              "name": "Ubuntu",
              "type": "linux",
              "family": "debian",
              "version": "20.04.6 LTS (Focal Fossa)",
              "platform": "ubuntu"
            },
            "containerized": true,
            "ip": [
              "172.18.0.7"
            ],
            "name": "docker-fleet-agent",
            "id": "009f8d5d825944429c9ae8d252b0019a",
            "mac": [
              "02-42-AC-12-00-07"
            ],
            "architecture": "x86_64"
          },
          "elastic_agent": {
            "id": "a7001b31-5e06-4cd3-98a6-150537020817",
            "version": "8.12.2",
            "snapshot": false
          },
          "event": {
            "agent_id_status": "verified",
            "ingested": "2024-12-11T12:24:28Z",
            "kind": "event",
            "module": "beyondinsight_password_safe",
            "category": [
              "iam"
            ],
            "type": [
              "info"
            ],
            "dataset": "beyondinsight_password_safe.managedaccount"
          }
        },
        "sort": [
          1733919867579
        ]
      }
 
```

The following non-ECS fields are used in managedaccount documents:

**Exported fields**

| Field | Target Field | Type |
|---|---|---|
|@timestamp (ECS field)|date
beyondinsight_password_safe.managedaccount|Data_stream.dataset (ECS field)|Constand_keyword
default|data_stream.namespace (ECS field)|constant_keyword
logs|data_stream.type (ECS field)|constant_keyword
“managedaccount”|tags (ECS field)|constant_keyword
cel|input.type (ECS field)|keyword
beyondinsight_password_safe.managedaccount. PlatformID|beyondinsight_password_safe.managedaccount. platform_id|keyword
beyondinsight_password_safe.managedaccount. SystemId|beyondinsight_password_safe.managedaccount. system_id|keyword
beyondinsight_password_safe.managedaccount. SystemName|beyondinsight_password_safe.managedaccount. system_name|keyword
beyondinsight_password_safe.managedaccount. DomainName|beyondinsight_password_safe.managedaccount. domain_name|keyword
beyondinsight_password_safe.managedaccount. AccountId|beyondinsight_password_safe.managedaccount. account_id|keyword
beyondinsight_password_safe.managedaccount. AccountName|beyondinsight_password_safe.managedaccount. account_name|keyword
beyondinsight_password_safe.managedaccount. InstanceName|beyondinsight_password_safe.managedaccount. instance_name|keyword
beyondinsight_password_safe.asset. UserPrincipalName|beyondtrust.asset. user_principal_name|keyword
beyondinsight_password_safe.managedaccount. ApplicationID|beyondinsight_password_safe.managedaccount. application_id|keyword
beyondinsight_password_safe.managedaccount. ApplicationDisplayName|beyondinsight_password_safe.managedaccount. application_display_name|keyword
beyondinsight_password_safe.managedaccount. DefaultReleaseDuration|beyondinsight_password_safe.managedaccount. default_release_duration|integer
beyondinsight_password_safe.managedaccount. MaximumReleaseDuration|beyondinsight_password_safe.managedaccount. maximum_release_duration|integer
beyondinsight_password_safe.managedaccount. LastChangeDate|beyondinsight_password_safe.managedaccount. last_change_date|date
beyondinsight_password_safe.managedaccount. NextChangeDate|beyondinsight_password_safe.managedaccount. Next_change_date|date
beyondinsight_password_safe.managedaccount. IsChanging|beyondinsight_password_safe.managedaccount. is_changing|bool
beyondinsight_password_safe.managedaccount. ChangeState|beyondinsight_password_safe.managedaccount. change_state|integer
beyondinsight_password_safe.managedaccount. IsISAAccess|beyondinsight_password_safe.managedaccount. is_is_access|bool
beyondinsight_password_safe.managedaccount. PreferredNodeID|beyondinsight_password_safe.managedaccount. preferred_node_id|keyword
