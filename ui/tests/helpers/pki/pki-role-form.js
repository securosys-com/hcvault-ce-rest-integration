/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

export const PKI_BASE_URL = `/vault/cluster/secrets/backend/pki/roles`;

export const SELECTORS = {
  roleName: '[data-test-input="name"]',
  issuerRef: '[data-test-input="issuerRef"]',
  issuerRefSelect: '[data-test-select="issuerRef"]',
  issuerRefToggle: '[data-test-toggle-label="issuerRef-toggle"]',
  customTtl: '[data-test-field="customTtl"]',
  backdateValidity: '[data-test-ttl-value="Backdate validity"]',
  maxTtl: '[data-test-toggle-label="Max TTL"]',
  generateLease: '[data-test-field="generateLease"]',
  noStore: '[data-test-field="noStore"]',
  addBasicConstraints: '[data-test-input="addBasicConstraints"]',
  domainHandling: '[data-test-toggle-group="Domain handling"]',
  keyParams: '[data-test-toggle-group="Key parameters"]',
  keyType: '[data-test-input="keyType"]',
  keyBits: '[data-test-input="keyBits"]',
  signatureBits: '[data-test-input="signatureBits"]',
  keyUsage: '[data-test-toggle-group="Key usage"]',
  extKeyUsageOids: '[data-test-input="extKeyUsageOids"]',
  digitalSignature: '[data-test-checkbox="DigitalSignature"]',
  keyAgreement: '[data-test-checkbox="KeyAgreement"]',
  keyEncipherment: '[data-test-checkbox="KeyEncipherment"]',
  any: '[data-test-checkbox="Any"]',
  serverAuth: '[data-test-checkbox="ServerAuth"]',
  policyIdentifiers: '[data-test-toggle-group="Policy identifiers"]',
  san: '[data-test-toggle-group="Subject Alternative Name (SAN) Options"]',
  additionalSubjectFields: '[data-test-toggle-group="Additional subject fields"]',
  roleCreateButton: '[data-test-pki-role-save]',
  roleCancelButton: '[data-test-pki-role-cancel]',
};
