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