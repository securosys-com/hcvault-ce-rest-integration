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

package hsm

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
)

const (
	NONE  string = "NONE"
	TOKEN string = "TOKEN"
	CERT  string = "CERT"
)

var logger hclog.Logger = hclog.New(&hclog.LoggerOptions{
	Name: fmt.Sprintf("securosys-hsm-seal")})

var Logs Logging

// This variable contains all server information
var RunTimeInfo = make(map[string]string)

// This variable contains information if Shutdown is triggered by the user
var ShutdownTriggered bool = false

// This variable enable/disable debug logs for Securosys Requests
var Debug bool

// Variable that stores entire configuration from yaml file
var configuration *Configurations

// This function validating a config_hsm.yml file
func (config *Configurations) checkConfigFile() bool {
	var valid bool = true
	var errors []string
	if config.Settings.CheckEvery == 0 {
		valid = false
		errors = append(errors, "check_every must be bigger then 0")
	}
	if config.Settings.ApprovalTimeout == 0 {
		valid = false
		errors = append(errors, "approval_timeout must be bigger then 0 and lower then VAULT_CLIENT_TIMEOUT. Default is 60 (seconds)\nYou can override this value by setting environment variable VAULT_CLIENT_TIMEOUT")
	}
	if config.Settings.ApprovalTimeout <= config.Settings.CheckEvery {
		valid = false
		errors = append(errors, "approval_timeout must be bigger then check_every")
	}
	if config.Settings.Auth == "" {
		valid = false
		errors = append(errors, "auth is empty. Must be the one of this values [TOKEN,CERT,NONE]")
	}
	if config.Settings.Auth != TOKEN && config.Settings.Auth != CERT && config.Settings.Auth != NONE {
		valid = false
		errors = append(errors, "auth must be the one of this values [TOKEN,CERT,NONE]")

	}
	if config.Settings.Auth == TOKEN {
		if config.Settings.BearerToken == "" {
			valid = false
			errors = append(errors, "bearer_token is empty")
		}
	}
	if config.Settings.Auth == CERT {
		if config.Settings.CertPath == "" {
			valid = false
			errors = append(errors, "cert_path is empty")
		} else {
			_, err := os.ReadFile(config.Settings.CertPath)
			if err != nil {
				valid = false
				errors = append(errors, "cert_path error on "+err.Error())
			}
		}
		if config.Settings.KeyPath == "" {
			valid = false
			errors = append(errors, "key_path is empty")
		} else {
			_, err := os.ReadFile(config.Settings.KeyPath)
			if err != nil {
				valid = false
				errors = append(errors, "key_path error on "+err.Error())
			}
		}
	}
	tsb := &TSBClient{
		Config: config,
	}
	_, err := tsb.CheckConnection()
	if err != nil {
		errors = append(errors, "Connection error: "+err.Error())
		valid = false
	}

	if !valid {
		for _, element := range errors {
			logger.Error(fmt.Sprintf("ERROR: %s\n", element))
		}
		logger.Error("Seal Configuration [securosys-hsm] is not valid:")
		if config.Settings.Debug != nil {
			Debug = *config.Settings.Debug
		}

		for _, element := range errors {
			logger.Error("Seal Configuration [securosys-hsm] is not valid:")
			logger.Error(fmt.Sprintf(" - %s\n", element))
		}
	}
	return valid
}

// Main function which one parse Yaml and adding settings into config variable
func InitConfig(debug bool) Configurations {
	Debug = debug
	if configuration != nil {
		if configuration.Settings.Debug != nil {
			Debug = *configuration.Settings.Debug
		}

		return *configuration
	}
	configuration = new(Configurations)
	if configuration.Settings.Debug != nil {
		Debug = *configuration.Settings.Debug
	}
	return *configuration
}
