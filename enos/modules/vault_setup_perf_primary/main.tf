# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
    }
  }
}

variable "vault_cluster_addr_port" {
  description = "The Raft cluster address port"
  type        = string
  default     = "8201"
}

variable "vault_install_dir" {
  type        = string
  description = "The directory where the Vault binary will be installed"
}

variable "primary_leader_public_ip" {
  type        = string
  description = "Vault primary cluster leader Public IP address"
}

variable "primary_leader_private_ip" {
  type        = string
  description = "Vault primary cluster leader Private IP address"
}

variable "vault_root_token" {
  type        = string
  description = "The vault root token"
}

resource "enos_remote_exec" "configure_pr_primary" {
  environment = {
    VAULT_ADDR        = "http://127.0.0.1:8200"
    VAULT_TOKEN       = var.vault_root_token
    VAULT_INSTALL_DIR = var.vault_install_dir
  }

  scripts = [abspath("${path.module}/scripts/configure-vault-pr-primary.sh")]

  transport = {
    ssh = {
      host = var.primary_leader_public_ip
    }
  }
}
