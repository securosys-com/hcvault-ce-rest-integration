/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import EditForm from 'core/components/edit-form';
import { computed } from '@ember/object';
import layout from '../templates/components/edit-form-kmip-role';

export default EditForm.extend({
  layout,
  model: null,

  cancelLink: computed('cancelLinkParams.[]', function () {
    if (!Array.isArray(this.cancelLinkParams) || !this.cancelLinkParams.length) return;
    const [route, ...models] = this.cancelLinkParams;
    return { route, models };
  }),

  init() {
    this._super(...arguments);

    if (this.model.isNew) {
      this.model.operationAll = true;
    }
  },

  actions: {
    toggleOperationSpecial(checked) {
      this.model.operationNone = !checked;
      this.model.operationAll = checked;
    },

    // when operationAll is true, we want all of the items
    // to appear checked, but we don't want to override what items
    // a user has selected - so this action creates an object that we
    // pass to the FormField component as the model instead of the real model
    placeholderOrModel(isOperationAll, attr) {
      return isOperationAll ? { [attr.name]: true } : this.model;
    },

    preSave(model) {
      // if we have operationAll or operationNone, we want to clear
      // out the others so that display shows the right data
      if (model.operationAll || model.operationNone) {
        model.operationFieldsWithoutSpecial.forEach((field) => model.set(field, null));
      }
      // set operationNone if user unchecks 'operationAll' instead of toggling the 'operationNone' input
      // doing here instead of on the 'operationNone' input because a user might deselect all, then reselect some options
      // and immediately setting operationNone will hide all of the checkboxes in the UI
      this.model.operationNone =
        model.operationFieldsWithoutSpecial.every((attr) => !model[attr]) && !this.model.operationAll;
    },
  },
});
