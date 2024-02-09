/*
Copyright (c) 2023 Securosys SA, authors: Tomasz Madej

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.
*/

package api

import (
	"context"
	"net/http"
)

func (c *Sys) UpdatePolicyHSM(opts *UpdatePolicyHSMRequest) (*UpdatePolicyHSMResponse, error) {
	return c.UpdatePolicyHSMWithContext(context.Background(), opts)
}

func (c *Sys) UpdatePolicyHSMWithContext(ctx context.Context, opts *UpdatePolicyHSMRequest) (*UpdatePolicyHSMResponse, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()
	r := c.c.NewRequest(http.MethodPut, "/v1/sys/update-policy-hsm")
	if err := r.SetJSONBody(opts); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result UpdatePolicyHSMResponse
	err = resp.DecodeJSON(&result)
	return &result, err
}

type UpdatePolicyHSMRequest struct {
	DisablePolicy bool              `json:"disable"`
	Policy        map[string]string `json:"policy"`
}

type UpdatePolicyHSMResponse struct {
	Status string `json:"status"`
	Error  error  `json:"error"`
}
