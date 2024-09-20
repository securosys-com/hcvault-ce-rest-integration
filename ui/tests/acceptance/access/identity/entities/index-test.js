/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import { currentRouteName } from '@ember/test-helpers';
import { module, test } from 'qunit';
import { setupApplicationTest } from 'ember-qunit';
import page from 'vault/tests/pages/access/identity/index';
import authPage from 'vault/tests/pages/auth';

module('Acceptance | /access/identity/entities', function (hooks) {
  setupApplicationTest(hooks);

  hooks.beforeEach(function () {
    return authPage.login();
  });

  test('it renders the entities page', async function (assert) {
    await page.visit({ item_type: 'entities' });
    assert.strictEqual(
      currentRouteName(),
      'vault.cluster.access.identity.index',
      'navigates to the correct route'
    );
  });

  test('it renders the groups page', async function (assert) {
    await page.visit({ item_type: 'groups' });
    assert.strictEqual(
      currentRouteName(),
      'vault.cluster.access.identity.index',
      'navigates to the correct route'
    );
  });
});
