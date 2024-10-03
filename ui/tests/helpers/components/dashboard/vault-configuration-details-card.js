/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

const SELECTORS = {
  cardTitle: '[data-test-configuration-details-title]',
  apiAddr: '[data-test-vault-config-details="api_addr"]',
  defaultLeaseTtl: '[data-test-vault-config-details="default_lease_ttl"]',
  maxLeaseTtl: '[data-test-vault-config-details="max_lease_ttl"]',
  tlsDisable: '[data-test-vault-config-details="tls"]',
  logFormat: '[data-test-vault-config-details="log_format"]',
  logLevel: '[data-test-vault-config-details="log_level"]',
  storageType: '[data-test-vault-config-details="type"]',
};

export default SELECTORS;
