# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

auto_auth {

  method {
    type = "token_file"

    config {
      token_file_path = "/Users/avean/.vault-token"
    }
  }
}

template_config {
  static_secret_render_interval = "5m"
  exit_on_retry_failure         = true
}

vault {
  address = "http://localhost:8200"
}

env_template "FOO_PASSWORD" {
  contents             = "{{ with secret \"secret/data/foo\" }}{{ .Data.data.password }}{{ end }}"
  error_on_missing_key = false
}
env_template "FOO_USER" {
  contents             = "{{ with secret \"secret/data/foo\" }}{{ .Data.data.user }}{{ end }}"
  error_on_missing_key = false
}

# Error: missing a required "exec" section!
