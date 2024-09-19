# Securosys Hashicorp Vault Integration 1.2.8
Issued: Sep, 5, 2024
## Update
- Updated core of Hashicorp Vault to 1.15.10.
## Feature
- added support for securosys-hsm seal options to parse new tsb policy
- added support for tsb api keys
- added support for RSA keypair to calculate metaDataSignature on seal
- modified builtin/logical/pki - added support keys on HSM using securosys-hsm plugin

# Securosys Hashicorp Vault Integration 1.2.7
Issued: Feb, 28, 2024
## Bugfix
- Fixed generating key, when migrate from Shamir to Securosys HSM Auto Unseal
- Removed wrong error message "auth is required", when optional check_every parameter is not exists in config.hcl 

# Securosys Hashicorp Vault Integration 1.2.6
Issued: Jan, 31, 2024
## Update
- Updated core of Hashicorp Vault to 1.15.5.

# Securosys Hashicorp Vault Integration 1.2.5
Issued: Dec, 6, 2023
## Update
- Updated core of Hashicorp Vault to 1.15.4.
## Bugfix
- Fixed authentication with TSB using mTLS

# Securosys Hashicorp Vault Integration 1.2.4
Issued: Dec, 4, 2023
## Update
- Updated core of Hashicorp Vault to 1.15.3.

# Securosys Hashicorp Vault Integration 1.2.3
Issued: Nov, 9, 2023
## Update
- Updated core of Hashicorp Vault to 1.15.2.

# Securosys Hashicorp Vault Integration 1.2.2
Issued: Oct, 26, 2023
## Feature
- Added posibility to provide full policy json from TSB to auto unseal configuration.

# Securosys Hashicorp Vault Integration 1.2.1
Issued: Oct, 25, 2023
## Update
- Updated core of Hashicorp Vault to 1.15.1.

# Securosys Hashicorp Vault Integration 1.2.0
Issued: Oct, 6, 2023
## Update
- Updated core of Hashicorp Vault to 1.15.0.

# Securosys Hashicorp Vault Integration 1.1.1
Issued: Sep, 18, 2023
## Bugfix
- Removed sending empty password char array on not provided password.

# Securosys Hashicorp Vault Integration 1.1.0
Issued: Aug, 7, 2023
## Compatibility
- This version is not compatible on the go with version **1.0.0**, If You are using **securosys-hsm** or **securosys-hsm-with-policy** **seal/unseal**

## Config Changes
- Modified method to active **seal/unseal** Vault using Securosys HSM
- Removed old **config-hsm.yml** files 
- Added new section to **config.hcl** to support native **auto unsealing** operations
- Modified example of **config.hcl**
  - Added example configuration for **auto unseal**
## Documentation Change
 - Modified all configuration files
 - Added section migration from **1.0.0** to **newer versions**

# Securosys Hashicorp Vault Integration 1.0.0
Issued: May, 26, 2023