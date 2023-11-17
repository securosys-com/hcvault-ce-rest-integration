/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import NamedPathAdapter from '../named-path';

export default class OidcScopeAdapter extends NamedPathAdapter {
  pathForType() {
    return 'identity/oidc/scope';
  }
}
