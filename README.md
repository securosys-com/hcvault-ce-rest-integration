# Securosys REST-based HSM integration in HashiCorp Vault CE

This HashiCorp Vault Community Edition update implements a platform-agnostic REST-based HSM interface with zero library installation, while eliminating connectivity hurdles by using secure web connections (TLS). This facilitates the use and deployment in clustered and multi-cloud environments. Moreover, Securosys HSM innovations like hardware enforced multi-authorization are at oneís disposal.
Security is paramount, experience Securosys Primus HSM or CloudsHSM integration without hassle from the very beginning.

- Unlock your Vault with the security of an HSM
- Make use of multi-authorization workflows for compliance applications

This integration is actively maintained by Securosys SA.

## Table of Contents

- [Glossary](#glossary)
- [Setup](#setup)

  - [Environment Variables](#environment-variables)

  - [Additional prerequisites for UI](#additional-prerequisites-for-ui)

- [How to build Vault CE](#how-to-build-vault-ce)

  - [Using pre-built releases](#using-pre-built-releases)
  - [Build from sources](#build-from-sources)

- [How to run Vault CE](#how-to-run-vault-ce)

  - [Developer Mode](#developer-mode)
  - [Production mode](#production-mode)
  - [Auto unseal (securosys-hsm)](#auto-unseal-securosys-hsm)
  - [Using Shamir Secrets](#using-shamir-secrets)
  - [Vault Server as Docker Image](#vault-server-as-docker-image)
- [Additional Vault Commands for Securosys HSM Integration](#additional-vault-commands-for-securosys-hsm-integration)
- [PKI Module](#pki-module)
  - [Requirements](#requirements)
  - [Additional Commands](#additional-commands)
    - [Generate new key and store it on hsm](#generate-new-key-and-store-it-on-hsm)
    - [Import cert and key to Vault PKI and store key on hsm](#import-cert-and-key-to-vault-pki-and-store-key-on-hsm)
    - [Import key to Vault PKI and store it on hsm](#import-key-to-hc-vault-pki-and-store-it-on-hsm)
  - [Working with PKI Module UI](#working-with-pki-module-ui)
    - [Retrieve lost key id](#retrieve-lost-key-id)
    - [Use generated/imported HSM Key](#use-generatedimported-key)

- [Example of config.hcl](#example-of-config.hcl)
- [Getting Support](#getting-support)
- [License](#license)
---

## Glossary

| Term      | Description                                                                           |
| :-------- | :------------------------------------------------------------------------------------ |
| CloudsHSM | HSM as a service, operated by Securosys                                               |
| HSM       | Hardware Security Module                                                              |
| JSON      | JavaScript Object Notation object                                                     |
| JWT       | JSON Web Token, used to authenticate and authorize users in web applications and APIs |
| SKA       | Smart Key Attributes, attributes adding rules to individual keys                      |
| TSB       | Transaction Security Broker, providing the REST interface                             |
| UI        | User Interface                                                                        |

## Setup

> **Prerequisites:** Install Golang 1.21.2 ([download](https://go.dev/dl/))

- On Windows : Add GOPATH and GOROOT manually to the system environment and restart your console.
  - GOPATH default `%USERPROFILE%\go`
  - GOROOT defaults to `%programfiles%`

### Environment Variables

`export VAULT_CLIENT_TIMEOUT=2000` This change is necessary, as the HashiCorp Vault default value is too low (60 seconds). The higher value is required for some operations (e.g. rekey) when waiting for an approved response.

### Additional prerequisites for UI

For the graphical User Interface the following packages must be installed on the machine:

- [Node.js](https://nodejs.org/dist/v16.17.1/) (with NPM) - version v16.17.1
- [Yarn](https://yarnpkg.com/en/) - Can be installed with the command `npm install -g yarn`

## How to build Vault CE

### Using pre-built releases

You can find pre-built releases of the Vault Community Edition on the Securosys JFrog artifactory. Download the latest binary file, corresponding to your target OS, configuration files, or docker image.

Further documentation and credentials are available via the [Securosys Support Portal](https://support.securosys.com/external/knowledge-base/article/192) or the Securosys [web-site](https://www.securosys.com/en/hashicorp-vault).

### Build from sources

There are multiple ways to build and run the Vault application.

To build Vault run either
`go build -o [executable_name]`
or use the command `make bin`
This will build it using the **Make file** configuration.
The Vault executable will be placed in the **bin** directory.

To build Vault with User Interface, run the following commands

- `make static-dist`
- `make bin`
  The Vault executable will be placed in the **bin** directory.

To build a docker image, run the following command
`make docker VERSION={$VERSION}` where {$VERSION} will be a version of the Securosys Vault image.

To build Vault executables for different platforms (Windows, MacOS, Linux, FreeBSD, NetBSD and OpenBSD)
`make release VERSION={$VERSION}` where {$VERSION} will be a version of build.

To build everything, docker image and all executables for all platforms
`make release-all VERSION={$VERSION}` where {$VERSION} will be a version of build.

## How to run Vault CE

You can run Vault without building it
`go run ./main.go [vault parameters]`

### Developer mode

To run the server in **dev mode** use either of the following commands
` go run ./main.go server -dev` or
`./executable_name server -dev`

In dev mode, all data is stored **only in memory** and **keys will be initialized every time**.

---

### Production mode

To run the server in **production mode** use either of the following commands
` go run ./main.go server -config=config.hcl` or
`./executable_name server -config=config.hcl`

Create the directory "**data**" (if it does not already exist).

If the Vault server is not yet initialized, then use either of the following commands
`go run ./main.go operator init -address http://127.0.0.1:8200` or
`./executable_name operator init -address http://127.0.0.1:8200`

These commands initialize the Vault server with default Vault encryption.

---

### Auto-Unseal (securosys-hsm)

Auto-unseal can be achieved via REST (TSB) interface, connected to Securosys Primus HSM or CloudsHSM.
In the configuration file **config.hcl** add the additional seal configuration section **seal "securosys-hsm"**:

```hcl
  seal "securosys-hsm" {
    //Define the unseal key stored on the HSM. If the key does not exist, a new key is created with the attributes defined in this file.
    key_label = "replace-me_key_label"
    //Key password
    key_password = "password"
    //RestApi url for calling requests to Securosys HSM via REST(TSB)
    tsb_api_endpoint = "replace-me_TSB_Endpoint" //https://rest-api.cloudshsm.com, https://sbx-rest-api.cloudshsm.com, https://primusdev.cloudshsm.com
    //Define the authorization type (TOKEN, CERT, NONE)
    auth = "TOKEN"
    //auth = TOKEN: define the JWT token to authorize at TSB
    bearer_token = "replace-me_BearerToken"
    //auth = CERT: mTLS, define the certificate to authorize at TSB
    //cert_path = "replace-me_with_cert_path"
    //Approval checking frequency in seconds
    check_every = 5
    //Wait for user approvals in seconds
    approval_timeout = 30

    //The following section defines the simple approval policy (SKA, ruleUse), applied only in case a new unseal key is created on the HSM.

    //FORMAT OBJECT:
    //name - RSA public key (pem)
    policy = <<EOF
    {
      "replace-me_nameOfApprover":"replace-me_ApproverPublicKey"
    }
    EOF
  }
```

> **policy**
> Define a simple SKA **ruleUse** policy, used for initializing the Vault when creating a new unseal key on the HSM. To use a full (complex) SKA policy, the key and policy must be created outside of Vault (e.g. via REST interface, Securosys Secrets Engine, ...). Vault will gather an existing unseal key policy from the HSM. If a policy exists on the unseal key, Vault will wait for all necessary approvals before unsealing (HSM enforced).

> **Note:** The configuration section **seal securosys-hsm** is only validated on startup of the **Hashicorp Vault Server**.

---

**_Important_**
After the `operator init` command Vault will print the Shamir **Unseal Keys** and the **Initial Root Token**:

```
Unseal Key 1: <unseal_key>
...
Initial Root Token: <root_key>
```

Note down these values, and store them in a safe place for disaster recovery.

---

#### Using Shamir Secrets

> **Note:** This works only with normal **Shamir** secrets. Using **seal "securosys-hsm"** the **Vault** is automatically unsealed on startup.

**Unseal** the server with the command
`vault operator unseal <unseal_key>`
and write system **env** with root token using this command
`vault login <root-token>`

Alternatively the [Web UI](http://localhost:8200/ui/) can be used.

## Vault Server as Docker Image

Prepare the additional configuration files for the docker image:

### File `docker-compose.yml`:

```yml
version: "3.3"
services:
  run:
    container_name: securosys_hashicorp_vault
    environment:
      - "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    volumes:
      - securosys_hashicorp_vault_config:/etc/app/config
      - securosys_hashicorp_vault_db:/etc/app/db
      - securosys_hashicorp_vault_plugins:/etc/app/plugins
    ports:
      - "0.0.0.0:8200:8200"
      - "0.0.0.0:8201:8201"
    image: securosys.jfrog.io/external-hashicorp-vault/1.1.1/securosys-hashicorp-vault:1.1.1.20230918145422
volumes:
  securosys_hashicorp_vault_config:
    driver: local
    driver_opts:
      o: bind
      type: none
      # Local absolute path to directory which contains all config files
      device: ./config/vault
  securosys_hashicorp_vault_db:
    driver: local
    driver_opts:
      o: bind
      type: none
      # Local absolute path to directory where we want to store database
      device: ./config/db
  securosys_hashicorp_vault_plugins:
    driver: local
    driver_opts:
      o: bind
      type: none
      # Local absolute path to directory where are stored custom plugins
      device: ./config/plugins
```

Where **{$version}** has to be replaced with the current version of the docker image.

### File `config.hcl`:

The configuration file differs slightly from the standalone version.

```hcl
//Example of config.hcl for Docker image.
//Addresses or paths are relative to path and addresses inside docker image

storage "raft" {
  path = "/etc/app/db" //Do not change this path
  node_id = "raft_node"
}

listener "tcp" {
  address     = "0.0.0.0:8200" //Do not change this path
  tls_disable = 1
}

disable_mlock=true
plugin_directory="/etc/app/plugins" //Do not change this path
api_addr = "http://0.0.0.0:8200" //Do not change this addr
cluster_addr = "https://127.0.0.1:8201" //Do not change this addr
ui = true

//Add below the config section seal "securosys-hsm" as shown in the auto-unseal chapter
```

## Additional Vault Commands for Securosys HSM Integration

`vault operator update-policy-hsm`
This command allows updating an RSA policy on the HSM. The command does **NOT CHANGE** an **RSA key** and **does not override the config.hcl** file.

The command has following additional parameters:

- `-disable` - Removes an SKA policy from the unseal key.
- `-policy` - Add a new SKA policy to the unseal key, using a **JSON** string. Example:
  ` "{\"name1\":\"public_key1\",\"name2\":\"public_key2\"}"`

> **Note**: This command can be useful e.g. when adding new approval clients, or changing clients key pair. It overrides an existing **policy** rule. The key attribute **modify** is required, and the SKA **ruleModify** policy must not be set (or empty).

## PKI Module
From version: **1.2.8**

PKI Module is modified to support [hcvault-plugin-secrets-engine](https://github.com/securosys-com/hcvault-plugin-secrets-engine) to generate keys on HSM and sign certificates using these keys.
All original PKI Module functionality are supported.
> **Note**: To use keys to creating issuer etc. always use keyId/key reference!

### Requirements
- Installed plugin [hcvault-plugin-secrets-engine](https://github.com/securosys-com/hcvault-plugin-secrets-engine)
- Configured [hcvault-plugin-secrets-engine](https://github.com/securosys-com/hcvault-plugin-secrets-engine) plugin

> ***Note** PKI Module needs at last one configured [hcvault-plugin-secrets-engine](https://github.com/securosys-com/hcvault-plugin-secrets-engine) on Hashicorp Vault. Keep that in mind that this modification use only **first** configured [hcvault-plugin-secrets-engine](https://github.com/securosys-com/hcvault-plugin-secrets-engine)

### Additional Commands
There are serval way to work with module.
- **Generate new key and store it on HSM** - with this endpoint key will be generater or registered as reference  to existing key on HSM
- **Import cert and key to Vault PKI and store key on HSM** - with scenario, when user wanted to import own certificate and private key to PKI.
- **Import key to HC Vault PKI and store it on HSM** - with scenario, when user wanted to import own private key to PKI.
> **Note** - All keys are stored as **reference** to existing keys on HSM

#### Generate new key and store it on HSM
This endpoint will generate key on HSM only when *string* sending in parameter **managed_key_name** are not exists as a key **label** on TSB. If PKI module found that key using name **managed_key_name** on TSB exists, then PKI module will store only the reference to this key

**POST** *http://127.0.0.1:8200/v1/pki/keys/generate/securosys-hsm*
``` 
    {
      "key_name":"key_name_in_pki",
      "key_type":"rsa",
      "key_bits":"4096",
      "managed_key_name":"key_name_on_hsm"
    }
```
Where:
- **key_type** - can be **rsa**, **ec** or **ed25519**
- **key_bits** - can be **2048**, **3072** or **4096** for **rsa key** and **254**, **256**, **384** or **521** for **ec key**. 
> **Note** - **key_bits** will be ignored for **ed25519 key**

Example response:
```
{
    "request_id": "08cc4c8b-bfa6-4175-f2ac-11c264dd8ac6",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "key_id": "eb2b44a3-d3c4-caf7-31c9-d91e292467bd",
        "key_name": "key_name_in_pki",
        "key_type": ""
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
``` 
> **Note**: *key_id* parameter is important to make this key work on Hashicorp Vault PKI Module UI. See section: [Working with PKI Module UI](#working-with-pki-module-ui)

#### Import cert and key to Vault PKI and store key on HSM
This endpoint provide option to import own certificate and private key to PKI Module.
> **Note** Key will be imported to HSM and stored in PKI Module as **reference**. 

**POST** *http://127.0.0.1:8200/v1/pki/issuers/import/securosys-hsm*
``` 
    {
      "pem_bundle":"-----BEGIN PRIVATE KEY-----\n PRIVATE KEY \n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\n PRIVATE KEY \n-----END CERTIFICATE-----\n"
    }
```
Where:
- **pem_bundle** - needs to be combined private key and certificate bundle

Example response:
```
{
    "request_id": "d8de0e3f-8d09-7f57-ce60-8056b7668b18",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "existing_issuers": null,
        "existing_keys": null,
        "imported_issuers": [
            "0be3e384-d114-b775-d7a9-4fb928ecc5b0"
        ],
        "imported_keys": [
            "8ccf569a-474d-1e94-8540-26ae96228e88"
        ],
        "mapping": {
            "0be3e384-d114-b775-d7a9-4fb928ecc5b0": "8ccf569a-474d-1e94-8540-26ae96228e88"
        }
    },
    "wrap_info": null,
    "warnings": [],
    "auth": null
}
```
> **Note**: *key_id* parameter is important to make this key work on Hashicorp Vault PKI Module UI. See section: [Working with PKI Module UI](#working-with-pki-module-ui)


#### Import key to HC Vault PKI and store it on HSM
This endpoint provide option to import own private key to PKI Module.
> **Note** Key will be imported to HSM and stored in PKI Module as **reference**. 

**POST** *http://127.0.0.1:8200/v11/pki/keys/import/securosys-hsm*
``` 
    {
      "key_name":"key_name_in_pki",
      "managed_key_name":"key_name_on_hsm",
      "pem_bundle":"-----BEGIN PRIVATE KEY-----\n PRIVATE KEY \n-----END PRIVATE KEY-----\n"
    }
```
Where:
- **pem_bundle** - needs to be private key

> **Note** - *managed_key_name* needs to be unique!.

Example response:
```
{
    "request_id": "37384e65-1b00-23eb-2104-343bfd1d5a24",
    "lease_id": "",
    "renewable": false,
    "lease_duration": 0,
    "data": {
        "key_id": "98995760-438d-cfc6-4ead-a38df12e9b7e",
        "key_name": "key_name_in_pki",
        "key_type": ""
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
```
> **Note**: reference in *imported_keys* array parameter is important to make this key work on Hashicorp Vault PKI Module UI. See section: [Working with PKI Module UI](#working-with-pki-module-ui)

### Working with PKI Module UI
UI for this module is not modified. However it is possible to work using key generated in HSM.
#### Retrieve lost key id
**KeyId** can be always found on **keys list** and **key details** on PKI Module UI
![Key id can be found in PKI Module key list ](readme_images/lost_key_id.png)

#### Use generated/imported key

Two steps are needed to use HSM key with PKI Module.
1) When UI provide option to choose key, please select **existing** key option. See screenshot below:
![Choose key type](readme_images/choose_key.png)
1) Next provide **keyid** to field showned below:
![Provide key id](readme_images/choose_key2.png)

## Example of config.hcl

```hcl
//Example of config.hcl for Docker image.
//Addresses or paths are relative to path and addresses inside docker image

storage "raft" {
  path = "/etc/app/db" //Do not change this path
  node_id = "raft_node"
}

listener "tcp" {
  address     = "0.0.0.0:8200" //Do not change this path
  tls_disable = 1
}

disable_mlock=true
plugin_directory="/etc/app/plugins" //Do not change this path
api_addr = "http://0.0.0.0:8200" //Do not change this addr
cluster_addr = "https://127.0.0.1:8201" //Do not change this addr
ui = true

seal "securosys-hsm" {
  //Define the unseal key stored on the HSM. If the key does not exist, a new key is created with the attributes defined in this file.
  key_label = "replace-me_key_label"
  //Key password
  key_password = "password"
  //RestApi url for calling requests to Securosys HSM via REST(TSB)
  tsb_api_endpoint = "replace-me_TSB_Endpoint" //https://rest-api.cloudshsm.com, https://sbx-rest-api.cloudshsm.com, https://primusdev.cloudshsm.com
  //Define the authorization type (TOKEN, CERT, NONE).
  auth = "TOKEN"
  //auth = TOKEN: define the JWT token to authorize at TSB
  bearer_token = "replace-me_BearerToken"
  //auth = CERT: mTLS, define the certificate to authorize at TSB
  cert_path = "replace-me_with_cert_path"
  key_path = "replace-me_with_key_path"
  //Approval checking frequency in seconds.
  check_every = 5
  //Wait for user approvals in seconds.
  approval_timeout = 30

  //The following section defines the simple approval policy (SKA, ruleUse), applied only in case a new unseal key is created on the HSM.

  //FORMAT OBJECT:
  //name - RSA public key (pem)
  policy = <<EOF
  {
    "replace-me_nameOfApprover":"replace-me_ApproverPublicKey"
  }
  EOF
  //or
  //Using full policy json
  full_policy = <<EOF
  {
    "ruleUse": {
      "tokens": [
        {
          "name": "string",
          "timelock": 0,
          "timeout": 0,
          "groups": [
            {
              "name": "string",
              "quorum": 0,
              "approvals": [
                {
                  "type": "public_key",
                  "name": "string",
                  "value": "string"
                }
              ]
            }
          ]
        }
      ]
    },
    "ruleBlock": {
      "tokens": [
        {
          "name": "string",
          "timelock": 0,
          "timeout": 0,
          "groups": [
            {
              "name": "string",
              "quorum": 0,
              "approvals": [
                {
                  "type": "public_key",
                  "name": "string",
                  "value": "string"
                }
              ]
            }
          ]
        }
      ]
    },
    "ruleUnblock": {
      "tokens": [
        {
          "name": "string",
          "timelock": 0,
          "timeout": 0,
          "groups": [
            {
              "name": "string",
              "quorum": 0,
              "approvals": [
                {
                  "type": "public_key",
                  "name": "string",
                  "value": "string"
                }
              ]
            }
          ]
        }
      ]
    },
    "ruleModify": {
      "tokens": [
        {
          "name": "string",
          "timelock": 0,
          "timeout": 0,
          "groups": [
            {
              "name": "string",
              "quorum": 0,
              "approvals": [
                {
                  "type": "public_key",
                  "name": "string",
                  "value": "string"
                }
              ]
            }
          ]
        }
      ]
    },
    "keyStatus": {
      "blocked": false
    }
  }
  EOF
  // or via file
  full_policy_file = path_to_file_policy.json

}
```
## Getting Support
**Community Support for Securosys open source software:**
In our Community we welcome contributions. The Community software is open source and community supported, there is no support SLA, but a helpful best-effort Community.

 - To report a problem or suggest a new feature, use the [Issues](https://github.com/securosys-com/hcvault-ce-rest-integration/issues) tab. 

**Commercial Support for REST/TSB and HSM related issues:** 
Securosys customers having an active support contract, open a support ticket via [Securosys Support Portal](https://support.securosys.com/external/service-catalogue/21).

**Getting a temporary CloudsHSM developer account:**
Check-out a time limited developer account by registering [here](https://app.securosys.com) and choosing *Trial Account*.

## License
 Securosys REST-based HSM integration in HashiCorp Vault CE is licensed under the HashiCorp Business Source License, please see [LICENSE](https://github.com/securosys-com/hcvault-ce-rest-integration/LICENSE). 

