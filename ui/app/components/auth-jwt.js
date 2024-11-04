/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import Ember from 'ember';
import { inject as service } from '@ember/service';
// ARG NOTE: Once you remove outer-html after glimmerizing you can remove the outer-html component
import Component from './outer-html';
import { task, timeout, waitForEvent } from 'ember-concurrency';
import { computed } from '@ember/object';
import { waitFor } from '@ember/test-waiters';

const WAIT_TIME = 500;
const ERROR_WINDOW_CLOSED =
  'The provider window was closed before authentication was complete. Your web browser may have blocked or closed a pop-up window. Please check your settings and click Sign In to try again.';
const ERROR_MISSING_PARAMS =
  'The callback from the provider did not supply all of the required parameters.  Please click Sign In to try again. If the problem persists, you may want to contact your administrator.';
const ERROR_JWT_LOGIN = 'OIDC login is not configured for this mount';
export { ERROR_WINDOW_CLOSED, ERROR_MISSING_PARAMS, ERROR_JWT_LOGIN };

export default Component.extend({
  store: service(),
  featureFlagService: service('featureFlag'),

  selectedAuthPath: null,
  selectedAuthType: null,
  roleName: null,
  role: null,
  errorMessage: null,
  onRoleName() {},
  onLoading() {},
  onError() {},
  onNamespace() {},

  didReceiveAttrs() {
    this._super();
    const debounce = !this.oldSelectedAuthPath && !this.selectedAuthPath;

    if (this.oldSelectedAuthPath !== this.selectedAuthPath || debounce) {
      this.fetchRole.perform(this.roleName, { debounce });
    }

    this.set('errorMessage', null);
    this.set('oldSelectedAuthPath', this.selectedAuthPath);
  },

  // Assumes authentication using OIDC until it's known that the mount is
  // configured for JWT authentication via static keys, JWKS, or OIDC discovery.
  isOIDC: computed('errorMessage', function () {
    return this.errorMessage !== ERROR_JWT_LOGIN;
  }),

  getWindow() {
    return this.window || window;
  },

  fetchRole: task(
    waitFor(function* (roleName, options = { debounce: true }) {
      if (options.debounce) {
        this.onRoleName(roleName);
        // debounce
        yield timeout(Ember.testing ? 0 : WAIT_TIME);
      }
      const path = this.selectedAuthPath || this.selectedAuthType;
      const id = JSON.stringify([path, roleName]);
      let role = null;
      try {
        role = yield this.store.findRecord('role-jwt', id, { adapterOptions: { namespace: this.namespace } });
      } catch (e) {
        // throwing here causes failures in tests
        if ((!e.httpStatus || e.httpStatus !== 400) && !Ember.testing) {
          throw e;
        }
        if (e.errors && e.errors.length > 0) {
          this.set('errorMessage', e.errors[0]);
        }
      }
      this.set('role', role);
    })
  ).restartable(),

  cancelLogin(oidcWindow, errorMessage) {
    this.closeWindow(oidcWindow);
    this.handleOIDCError(errorMessage);
  },

  closeWindow(oidcWindow) {
    this.watchPopup.cancelAll();
    this.watchCurrent.cancelAll();
    oidcWindow.close();
  },

  handleOIDCError(err) {
    this.onLoading(false);
    this.prepareForOIDC.cancelAll();
    this.onError(err);
  },

  prepareForOIDC: task(function* (oidcWindow) {
    const thisWindow = this.getWindow();
    // show the loading animation in the parent
    this.onLoading(true);
    // start watching the popup window and the current one
    this.watchPopup.perform(oidcWindow);
    this.watchCurrent.perform(oidcWindow);
    // wait for message posted from oidc callback
    // see issue https://github.com/hashicorp/vault/issues/12436
    // ensure that postMessage event is from expected source
    while (true) {
      const event = yield waitForEvent(thisWindow, 'message');
      if (event.origin === thisWindow.origin && event.isTrusted && event.data.source === 'oidc-callback') {
        return this.exchangeOIDC.perform(event.data, oidcWindow);
      }
      // continue to wait for the correct message
    }
  }),

  watchPopup: task(function* (oidcWindow) {
    while (true) {
      yield timeout(WAIT_TIME);
      if (!oidcWindow || oidcWindow.closed) {
        return this.handleOIDCError(ERROR_WINDOW_CLOSED);
      }
    }
  }),

  watchCurrent: task(function* (oidcWindow) {
    // when user is about to change pages, close the popup window
    yield waitForEvent(this.getWindow(), 'beforeunload');
    oidcWindow.close();
  }),

  exchangeOIDC: task(function* (oidcState, oidcWindow) {
    if (oidcState === null || oidcState === undefined) {
      return;
    }
    this.onLoading(true);

    let { namespace, path, state, code } = oidcState;

    // The namespace can be either be passed as a query parameter, or be embedded
    // in the state param in the format `<state_id>,ns=<namespace>`. So if
    // `namespace` is empty, check for namespace in state as well.
    if (namespace === '' || this.featureFlagService.managedNamespaceRoot) {
      const i = state.indexOf(',ns=');
      if (i >= 0) {
        // ",ns=" is 4 characters
        namespace = state.substring(i + 4);
        state = state.substring(0, i);
      }
    }

    if (!path || !state || !code) {
      return this.cancelLogin(oidcWindow, ERROR_MISSING_PARAMS);
    }
    const adapter = this.store.adapterFor('auth-method');
    this.onNamespace(namespace);
    let resp;
    // do the OIDC exchange, set the token on the parent component
    // and submit auth form
    try {
      resp = yield adapter.exchangeOIDC(path, state, code);
      this.closeWindow(oidcWindow);
    } catch (e) {
      // If there was an error on Vault's end, close the popup
      // and show the error on the login screen
      return this.cancelLogin(oidcWindow, e);
    }
    yield this.onSubmit(null, null, resp.auth.client_token);
  }),

  actions: {
    async startOIDCAuth(data, e) {
      this.onError(null);
      if (e && e.preventDefault) {
        e.preventDefault();
      }
      try {
        await this.fetchRole.perform(this.roleName, { debounce: false });
      } catch (error) {
        // this task could be cancelled if the instances in didReceiveAttrs resolve after this was started
        if (error?.name !== 'TaskCancelation') {
          throw error;
        }
      }
      if (!this.isOIDC || !this.role || !this.role.authUrl) {
        let message = this.errorMessage;
        if (!this.role) {
          message = 'Invalid role. Please try again.';
        } else if (!this.role.authUrl) {
          message =
            'Missing auth_url. Please check that allowed_redirect_uris for the role include this mount path.';
        }
        this.onError(message);
        return;
      }
      const win = this.getWindow();

      const POPUP_WIDTH = 500;
      const POPUP_HEIGHT = 600;
      const left = win.screen.width / 2 - POPUP_WIDTH / 2;
      const top = win.screen.height / 2 - POPUP_HEIGHT / 2;
      const oidcWindow = win.open(
        this.role.authUrl,
        'vaultOIDCWindow',
        `width=${POPUP_WIDTH},height=${POPUP_HEIGHT},resizable,scrollbars=yes,top=${top},left=${left}`
      );

      this.prepareForOIDC.perform(oidcWindow);
    },
  },
});
