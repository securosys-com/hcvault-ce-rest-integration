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
  //You can use existing keyLabel or new key
  key_label = "replace-me_key_label" 
  //Key password
  key_password = "password"
  //RestApi url for calling requests to Securosys HSM (TSB)
  tsb_api_endpoint = "replace-me_TSB_Endpoint" //https://rest-api.cloudshsm.com, https://sbx-rest-api.cloudshsm.com, https://primusdev.cloudshsm.com
  //This parameter defines authorization type. It can be NONE,TOKEN,CERT
  auth = "TOKEN"
  //This is a token needed access to rest api if auth = TOKEN
  bearer_token = "replace-me_BearerToken"
  //There are a certificate and key path needed access to rest api if auth = CERT
  cert_path = "replace-me_with_cert_path"
  key_path = "replace-me_with_key_path"
  //This parameter show frequency of checking approvals in seconds. For this case it will be 1 request per 10 seconds. 
  check_every = 5
  //This parameter defines timeout on waiting for users approvals in seconds. 
  approval_timeout = 30
  //This section contains list of approvals that be needed to unseal Hashicorp Vault
  //FORMAT OBJECT: 
  //name - RSA public key (pem)
  policy = <<EOF
  { 
    "replace-me_nameOfApprover":"replace-me_ApproverPublicKey" 
  }
  EOF
}