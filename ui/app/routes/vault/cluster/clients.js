/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import Route from '@ember/routing/route';
import { hash } from 'rsvp';
import { action } from '@ember/object';
import getStorage from 'vault/lib/token-storage';
import { inject as service } from '@ember/service';
const INPUTTED_START_DATE = 'vault:ui-inputted-start-date';

export default class ClientsRoute extends Route {
  @service store;
  async getVersionHistory() {
    return this.store
      .findAll('clients/version-history')
      .then((response) => {
        return response.map(({ version, previousVersion, timestampInstalled }) => {
          return {
            version,
            previousVersion,
            timestampInstalled,
          };
        });
      })
      .catch(() => []);
  }

  model() {
    // swallow config error so activity can show if no config permissions
    return hash({
      config: this.store.queryRecord('clients/config', {}).catch(() => {}),
      versionHistory: this.getVersionHistory(),
    });
  }

  @action
  deactivate() {
    // when navigating away from parent route, delete manually inputted license start date
    getStorage().removeItem(INPUTTED_START_DATE);
  }
}
