/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import { create, attribute, visitable, collection, hasClass, text } from 'ember-cli-page-object';

export default create({
  visit: visitable('/vault/access/'),
  methodsLink: {
    isActive: hasClass('active'),
    text: text(),
    scope: '[data-test-sidebar-nav-link="Authentication Methods"]',
  },

  backendLinks: collection('[data-test-auth-backend-link]', {
    path: text('[data-test-path]'),
    id: attribute('data-test-id', '[data-test-path]'),
  }),

  findLinkById(id) {
    return this.backendLinks.filterBy('id', id)[0];
  },
});
