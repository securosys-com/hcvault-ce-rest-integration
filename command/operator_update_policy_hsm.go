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

package command

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mitchellh/cli"
	"github.com/posener/complete"

	"github.com/hashicorp/vault/api"
)

var (
	_ cli.Command             = (*OperatorUpdatePolicyHSMCommand)(nil)
	_ cli.CommandAutocomplete = (*OperatorUpdatePolicyHSMCommand)(nil)
)

type OperatorUpdatePolicyHSMCommand struct {
	*BaseCommand
	flagDisablePolicy bool
	flagNewPolicy     string
}

func (c *OperatorUpdatePolicyHSMCommand) Synopsis() string {
	return "Updates policy for SecurosysHSM"
}

func (c *OperatorUpdatePolicyHSMCommand) Help() string {
	helpText := `
Usage: vault operator update-policy-hsm

  This operation updates policy for SecurosysHSM. This method only edit/updates
  the policy settings. Keys are remain unchaged.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *OperatorUpdatePolicyHSMCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP | FlagSetOutputFormat)

	// Common Options
	f := set.NewFlagSet("Common Options")
	f.BoolVar(&BoolVar{
		Name:       "disable",
		Target:     &c.flagDisablePolicy,
		Default:    false,
		Completion: complete.PredictAnything,
		Usage:      "Disable policy in key for SecurosysHSM",
	})
	f.StringVar(&StringVar{
		Name:       "policy",
		Target:     &c.flagNewPolicy,
		Default:    "",
		Completion: complete.PredictAnything,
		Usage:      "New policy in object json format for SecurosysHSM key",
	})

	return set
}

func (c *OperatorUpdatePolicyHSMCommand) AutocompleteArgs() complete.Predictor {
	return nil
}

func (c *OperatorUpdatePolicyHSMCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *OperatorUpdatePolicyHSMCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	args = f.Args()
	if len(args) > 0 {
		c.UI.Error(fmt.Sprintf("Too many arguments (expected 0, got %d)", len(args)))
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	// Set defaults based on use of auto unseal seal
	// client.Sys().SealStatus()
	// if err != nil {
	// 	c.UI.Error(err.Error())
	// 	return 2
	// }
	// fmt.Println(sealInfo)
	// Build the initial init request

	policyStr := c.flagNewPolicy
	var policy map[string]string

	if policyStr != "" {
		err = json.Unmarshal([]byte(policyStr), &policy)
		if err != nil {
			c.UI.Error(err.Error())
			return 2
		}
	}
	initReq := &api.UpdatePolicyHSMRequest{
		DisablePolicy: c.flagDisablePolicy,
		Policy:        policy,
	}

	// Check auto mode
	return c.init(client, initReq)
}

func (c *OperatorUpdatePolicyHSMCommand) init(client *api.Client, req *api.UpdatePolicyHSMRequest) int {
	_, err := client.Sys().UpdatePolicyHSM(req)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing: %s", err))
		return 2
	}
	// fmt.Println(resp)
	c.UI.Output(fmt.Sprintf("Sucessfully changed the key policy"))
	return 0
}
