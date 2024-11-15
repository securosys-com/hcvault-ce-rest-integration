#!/bin/bash
function prop {
    grep "${1}" ${file} | cut -d'=' -f2
}
function get_version_part {
    local version="$1"
    local part="$2"

    # Split the version using IFS
    IFS='.' read -r major minor patch <<< "$version"

    case "$part" in
        major)
            echo "$major"
            ;;
        minor)
            echo "$minor"
            ;;
        patch)
            echo "$patch"
            ;;
        *)
            echo "Invalid part specified. Use 'major', 'minor', or 'patch'."
            return 1
            ;;
    esac
}
function compare_versions {
    major_user=`get_version_part $1 "major"`
    major_src=`get_version_part $2 "major"`
    if [ "$major_user" != "$major_src" ]; then
        echo "Major version are diferent. Cannot continue"
        exit 1
    fi
    minor_user=`get_version_part $1 "minor"`
    minor_src=`get_version_part $2 "minor"`
    if [ "$minor_user" != "$minor_src" ]; then
        echo "Minor version are diferent. Cannot continue"
        exit 1
    fi
    patch_user=`get_version_part $1 "patch"`
    patch_src=`get_version_part $2 "patch"`
    if [ "$patch_user" -gt "$patch_src" ]; then
        echo "Version path is greater than HC Vault version"
    fi
}
function newLine {
    printf "\n"
}



echo "Welcome to HC Vault - Securosys Integration";
echo "Select version to download: "

my_array=("1.2.10","1.2.11")

for index in "${!my_array[@]}"; do
    echo "$index) - ${my_array[$index]}"
done
read -p "Select version: " SELECTED_VERSION

# Replace USER, REPO, and TAG_NAME with actual values
mkdir -p temp
curl -L -o temp/hc_vault.zip -O https://github.com/securosys-com/hcvault-ce-rest-integration/archive/refs/tags/v${my_array[$SELECTED_VERSION]}.zip
cd temp && unzip hc_vault.zip
cd ..
rm temp/hc_vault.zip
PATH_SRC_TO_VAULT=temp/hcvault-ce-rest-integration-${my_array[$SELECTED_VERSION]}

file="./$PATH_SRC_TO_VAULT/project.properties"
echo "- Core (HC Vault) Version: "$(prop 'CORE')
echo "- Project Version: "$(prop 'VERSION')
SRC_VAULT_VERSION=$(prop 'CORE')
echo "Please provide path to your HC Vault source code"
read -p "Path: " USER_VAULT_PATH
USER_VAULT_PATH="${USER_VAULT_PATH//\'/}"
USER_VAULT_VERSION=`cat "$USER_VAULT_PATH/version/VERSION"`
echo "Source code version: "$USER_VAULT_VERSION
compare_versions $USER_VAULT_VERSION $SRC_VAULT_VERSION

newLine
read -p "Do You want to copy securosys-hsm auto-sealing? (y/n): " USER_AUTO_SEALING_CHOICE

if [ "$USER_AUTO_SEALING_CHOICE" == "y" ]; then
    echo "Following changes will be result after activation:"
    echo "NEW FILES:"
    echo "  COPY $PATH_SRC_TO_VAULT/hsm -> $USER_VAULT_PATH/hsm - added securosys-hsm kms wrapper"
    echo "MODIFIED FILES:"
    echo "  COPY $PATH_SRC_TO_VAULT/api/client.go -> $USER_VAULT_PATH/api/client.go - extended timeout to 999999"
    echo "  COPY $PATH_SRC_TO_VAULT/internalshared/configutil/kms.go -> $USER_VAULT_PATH/internalshared/configutil/kms.go - added new seucrosys_hsm kms wrapper and initialize method"
    echo "  COPY $PATH_SRC_TO_VAULT/vault/seal/seal_wrapper.go -> $USER_VAULT_PATH/vault/seal/seal_wrapper.go - modify health check operation for securosys_hsm wrapper"

    read -p "Do You REALLY want to to continue? (y/n): " USER_AUTO_SEALING_CHOICE_CONFIRM
    if [ "$USER_AUTO_SEALING_CHOICE_CONFIRM" == "y" ]; then
        cp -R -f $PATH_SRC_TO_VAULT/hsm $USER_VAULT_PATH/hsm
        cp $PATH_SRC_TO_VAULT/api/client.go $USER_VAULT_PATH/api/client.go      
        cp $PATH_SRC_TO_VAULT/internalshared/configutil/kms.go $USER_VAULT_PATH/internalshared/configutil/kms.go      
        cp $PATH_SRC_TO_VAULT/vault/seal/seal_wrapper.go $USER_VAULT_PATH/vault/seal/seal_wrapper.go     
        if grep -q "replace securosys.ch/hsm => ./hsm" $USER_VAULT_PATH/go.mod; then
            echo "Library 'securosys.ch/hsm' already added to go.mod. No need to change"
        else
            lineNumber=`grep -n '^toolchain' $USER_VAULT_PATH/go.mod  | cut -d: -f1`
            newString="replace securosys.ch/hsm => ./hsm"
            awk -v ln="$lineNumber" -v str="$newString" 'NR==ln{print; print str; next}1' $USER_VAULT_PATH/go.mod > temp && mv temp $USER_VAULT_PATH/go.mod
        fi
        echo "TESTING BUILD"
        cd $USER_VAULT_PATH && go mod tidy && go build -o delme && rm delme

        echo "Successfully added: securosys-hsm auto-sealing"
    else 
        echo "OPERATION ABORTED"
    fi
    

fi
newLine
read -p "Do You want to copy pki-modification? (y/n): " USER_PKI_MODIFICATION_CHOICE
if [ "$USER_PKI_MODIFICATION_CHOICE" == "y" ]; then
    echo "Following changes will be result after activation:"
    echo "MODIFIED FILES:"
    echo "  COPY $PATH_SRC_TO_VAULT/builtin/logical/pki -> $USER_VAULT_PATH/builtin/logical/pki - added support for HC Vault Securosys Secrets Engine"
    echo "  COPY $PATH_SRC_TO_VAULT/sdk/logical/request.go -> $USER_VAULT_PATH/sdk/logical/request.go - added new properties Host and ClientTokenOrig"
    echo "  COPY $PATH_SRC_TO_VAULT/vault/router.go -> $USER_VAULT_PATH/vault/router.go - added initialization for new variable"
    echo "  COPY $PATH_SRC_TO_VAULT/http/logical.go -> $USER_VAULT_PATH/http/logical.go - added initialization for new variable"
    echo "  COPY $PATH_SRC_TO_VAULT/api/request.go -> $USER_VAULT_PATH/api/request.go - added initialization for new variable"

    read -p "Do You REALLY want to to continue? (y/n): " USER_PKI_MODIFICATION_CHOICE_CONFIRM
    if [ "$USER_PKI_MODIFICATION_CHOICE_CONFIRM" == "y" ]; then
        cp -R -f $PATH_SRC_TO_VAULT/builtin/logical/pki $USER_VAULT_PATH/builtin/logical/pki
        cp $PATH_SRC_TO_VAULT/sdk/logical/request.go $USER_VAULT_PATH/sdk/logical/request.go    
        cp $PATH_SRC_TO_VAULT/vault/router.go $USER_VAULT_PATH/vault/router.go
        cp $PATH_SRC_TO_VAULT/http/logical.go $USER_VAULT_PATH/http/logical.go     
        cp $PATH_SRC_TO_VAULT/api/request.go $USER_VAULT_PATH/api/request.go     
        echo "TESTING BUILD"
        cd $USER_VAULT_PATH && go mod tidy && go build -o delme && rm delme

        echo "Successfully added: pki-modification"
    else 
        echo "OPERATION ABORTED"
    fi
    

fi
rm -rf $PATH_SRC_TO_VAULT