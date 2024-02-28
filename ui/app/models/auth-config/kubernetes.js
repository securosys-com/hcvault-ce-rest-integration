/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import { attr } from '@ember-data/model';
import { computed } from '@ember/object';

import AuthConfig from '../auth-config';
import { combineFieldGroups } from 'vault/utils/openapi-to-attrs';
import fieldToAttrs from 'vault/utils/field-to-attrs';

export default AuthConfig.extend({
  useOpenAPI: true,
  kubernetesHost: attr('string', {
    helpText:
      'Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server',
  }),

  kubernetesCaCert: attr('string', {
    editType: 'file',
    helpText: 'PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API',
  }),

  tokenReviewerJwt: attr('string', {
    helpText:
      'A service account JWT used to access the TokenReview API to validate other JWTs during login. If not set the JWT used for login will be used to access the API',
  }),

  pemKeys: attr({
    editType: 'stringArray',
  }),

  fieldGroups: computed('newFields', function () {
    let groups = [
      {
        default: ['kubernetesHost', 'kubernetesCaCert'],
      },
      {
        'Kubernetes Options': ['tokenReviewerJwt', 'pemKeys'],
      },
    ];
    if (this.newFields) {
      groups = combineFieldGroups(groups, this.newFields, []);
    }

    return fieldToAttrs(this, groups);
  }),
});
