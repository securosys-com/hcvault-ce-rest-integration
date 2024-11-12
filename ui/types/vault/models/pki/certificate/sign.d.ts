/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import PkiCertificateBaseModel from './base';
import { FormField, FormFieldGroups, ModelValidations } from 'vault/app-types';
export default class PkiCertificateSignModel extends PkiCertificateBaseModel {
  role: string;
  csr: string;
  formFields: FormField[];
  formFieldGroups: FormFieldGroups;
  removeRootsFromChain: boolean;
  validate(): ModelValidations;
}
