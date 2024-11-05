/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import { inject as service } from '@ember/service';
import Component from '@ember/component';

export default Component.extend({
  tagName: '',
  version: service(),
});
