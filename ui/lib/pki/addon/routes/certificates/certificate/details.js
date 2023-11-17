/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';

export default class PkiCertificateDetailsRoute extends Route {
  @service store;
  @service secretMountPath;

  model() {
    const id = this.paramsFor('certificates/certificate').serial;
    return this.store.queryRecord('pki/certificate/base', { backend: this.secretMountPath.currentPath, id });
  }
  setupController(controller, model) {
    super.setupController(controller, model);
    controller.breadcrumbs = [
      { label: 'secrets', route: 'secrets', linkExternal: true },
      { label: this.secretMountPath.currentPath, route: 'overview' },
      { label: 'certificates', route: 'certificates.index' },
      { label: model.id },
    ];
  }
}
