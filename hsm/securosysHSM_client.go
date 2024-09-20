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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const (
	EnvAdditionalAuthenticationData = "SECUROSYSHSM_ADDITIONAL_AUTHENTICATION_DATA"
	EnvTagLength                    = "SECUROSYSHSM_TAG_LENGTH"
	EnvCipherAlgorithm              = "SECUROSYSHSM_CIPHER_ALGORITHM"
)

type securosysHSMClientEncryptor interface {
	Close()
	Encrypt(plaintext string) (data []byte, err error)
	Decrypt(ciphertext string, keyVersion string, initializationVector string) (plaintext []byte, err error)
}

type SecurosysHSMClient struct {
	keyLabel                     string
	keyPassword                  string
	cipherAlgorithm              string
	additionalAuthenticationData string
	tagLength                    string
	tsbClient                    *TSBClient
	key                          string
}

func newSecurosysHSMClient(logger hclog.Logger, opts *options) (*SecurosysHSMClient, *wrapping.WrapperConfig, error) {
	var keyLabel, tagLength, keyPassword, cipherAlgorithm, certPath, keyPath, additionalAuthenticationData, approvalTimeout, auth, bearerToken, checkEvery, tsbApiEndpoint string
	var wrapperConfig *Configurations = new(Configurations)

	switch {
	case opts.withKeyLabel != "":
		keyLabel = opts.withKeyLabel
	default:
		return nil, nil, fmt.Errorf("key_label is required")
	}

	switch {
	case opts.withKeyPassword != "":
		keyPassword = opts.withKeyPassword
	}
	switch {
	case opts.withApprovalTimeout != "":
		approvalTimeout = opts.withApprovalTimeout
	default:
		approvalTimeout = "60"

	}
	var policyPart map[string]map[string]string = make(map[string]map[string]string)
	policyStr := ""
	policyType := 0

	if opts.withPolicy != "" {
		simplyPolicy := strings.Replace(opts.withPolicy, "\n", "", -1)
		policyType = 1
		policyStr = simplyPolicy
	} else if opts.withPolicyRuleUse != "" || opts.withPolicyRuleBlock != "" || opts.withPolicyRuleUnBlock != "" || opts.withPolicyRuleModify != "" {
		if opts.withPolicyRuleUse != "" {
			simplyPolicy := strings.Replace(opts.withPolicyRuleUse, "\n", "", -1)
			policyType = 2
			policyPart["use"] = make(map[string]string)
			var temp map[string]string
			err := json.Unmarshal([]byte(simplyPolicy), &temp)
			if err != nil {
				logger.Error("Rule 'use' is not valid. Error: %s\n", err)
				os.Exit(1)
			}
			policyPart["use"] = temp

		}
		if opts.withPolicyRuleBlock != "" {
			simplyPolicy := strings.Replace(opts.withPolicyRuleBlock, "\n", "", -1)
			policyType = 2
			policyPart["block"] = make(map[string]string)
			var temp map[string]string
			err := json.Unmarshal([]byte(simplyPolicy), &temp)
			if err != nil {
				logger.Error("Rule 'block' is not valid. Error: %s\n", err)
				os.Exit(1)
			}
			policyPart["block"] = temp
		}
		if opts.withPolicyRuleUnBlock != "" {
			simplyPolicy := strings.Replace(opts.withPolicyRuleUnBlock, "\n", "", -1)
			policyType = 2
			policyPart["unblock"] = make(map[string]string)
			var temp map[string]string
			err := json.Unmarshal([]byte(simplyPolicy), &temp)
			if err != nil {
				logger.Error("Rule 'unblock' is not valid. Error: %s\n", err)
				os.Exit(1)
			}
			policyPart["unblock"] = temp
		}
		if opts.withPolicyRuleModify != "" {
			simplyPolicy := strings.Replace(opts.withPolicyRuleModify, "\n", "", -1)
			policyType = 2
			policyPart["modify"] = make(map[string]string)
			var temp map[string]string
			err := json.Unmarshal([]byte(simplyPolicy), &temp)
			if err != nil {
				logger.Error("Rule 'modify' is not valid. Error: %s\n", err)
				os.Exit(1)
			}
			policyPart["modify"] = temp
		}
	} else if opts.withFullPolicy != "" {
		policyStr = opts.withFullPolicy
		policyType = 0
	} else if opts.withFullPolicyFile != "" {
		policyFilePath := opts.withFullPolicyFile
		data, err := os.ReadFile(policyFilePath)
		if err != nil {
			logger.Error("Error on reading policy file. Error: %s\n", err)
			os.Exit(1)
		}
		policyStr = string(data[:])
		policyType = 0
	} else {
		policyType = 1
		policyStr = "{}"
	}
	if policyType == 0 {
		var err error
		wrapperConfig.Policy, err = PreparePolicy(policyStr, policyType)
		if err != nil {
			logger.Error("Something wrong on full policy json. Error: %s\n", err)
			os.Exit(1)
		}
	} else if policyType == 1 {
		var err error
		wrapperConfig.Policy, err = PreparePolicy(policyStr, policyType)
		if err != nil {
			logger.Error("Something wrong on policy. Error: %s\n", err)
			os.Exit(1)
		}
	} else {
		var err error
		data, _ := json.Marshal(policyPart)
		wrapperConfig.Policy, err = PreparePolicy(string(data[:]), 2)
		if err != nil {
			logger.Error("Something wrong on policy. Error: %s\n", err)
			os.Exit(1)
		}

	}

	switch {
	case opts.withAuth != "":
		auth = opts.withAuth
	default:
		return nil, nil, fmt.Errorf("auth is required")
	}
	switch {
	case opts.withBearerToken != "":
		bearerToken = opts.withBearerToken
	}
	switch {
	case opts.withCertPath != "":
		certPath = opts.withCertPath
	}
	switch {
	case opts.withKeyPath != "":
		keyPath = opts.withKeyPath
	}
	switch {
	case opts.withCheckEvery != "":
		checkEvery = opts.withCheckEvery
	}
	switch {
	case opts.withTSBApiEndpoint != "":
		tsbApiEndpoint = opts.withTSBApiEndpoint
	default:
		return nil, nil, fmt.Errorf("tsb_api_endpoint is required")
	}
	var keyPair KeyPair
	json.Unmarshal([]byte(opts.withApplicationKeyPair), &keyPair)
	var apiKeys ApiKeyTypes
	json.Unmarshal([]byte(opts.withApiKeys), &apiKeys)

	wrapperConfig.Settings.RestApi = tsbApiEndpoint
	wrapperConfig.Settings.Auth = auth
	wrapperConfig.Settings.BearerToken = bearerToken
	wrapperConfig.Settings.CertPath = certPath
	wrapperConfig.Settings.KeyPath = keyPath
	wrapperConfig.Key.RSALabel = keyLabel
	wrapperConfig.Key.RSAPassword = keyPassword
	wrapperConfig.Settings.ApplicationKeyPair = keyPair
	wrapperConfig.Settings.ApiKeys = apiKeys
	configuration = wrapperConfig

	data, err := strconv.Atoi(checkEvery)
	if err == nil {
		wrapperConfig.Settings.CheckEvery = data
	}
	data, err = strconv.Atoi(approvalTimeout)
	if err == nil {
		wrapperConfig.Settings.ApprovalTimeout = data
	}
	valid := wrapperConfig.checkConfigFile()
	if !valid {
		os.Exit(1)
	}
	tsbClient := &TSBClient{
		Config: wrapperConfig,
	}
	client := &SecurosysHSMClient{
		tsbClient:                    tsbClient,
		keyLabel:                     keyLabel,
		additionalAuthenticationData: additionalAuthenticationData,
		keyPassword:                  keyPassword,
		tagLength:                    tagLength,
		cipherAlgorithm:              cipherAlgorithm,
	}
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["tsb_api_endpoint"] = tsbApiEndpoint
	wrapConfig.Metadata["check_every"] = checkEvery
	wrapConfig.Metadata["key_label"] = keyLabel
	wrapConfig.Metadata["auth"] = auth
	// wrapConfig.Metadata["bearer_token"] = bearerToken
	// wrapConfig.Metadata["cert_path"] = certPath
	// wrapConfig.Metadata["key_path"] = keyPath
	wrapConfig.Metadata["approval_timeout"] = approvalTimeout
	// wrapConfig.Metadata["key_password"] = keyPassword

	key, err, code := tsbClient.GetKeyAttributes(keyLabel, keyPassword)
	if err != nil || code == 404 {
		_, body, code, _ := tsbClient.GenerateRSAKey(wrapperConfig.Policy, keyLabel, keyPassword)
		if code != 201 {
			return client, wrapConfig, fmt.Errorf("Error on creating RSA Key: %s", body)
		}
		key, _, _ := tsbClient.GetKeyAttributes(keyLabel, keyPassword)
		tsbClient.Config.Key.KeyAttributes = key
	} else {
		tsbClient.Config.Key.KeyAttributes = key
	}

	return client, wrapConfig, err
}

func (c *SecurosysHSMClient) Encrypt(plaintext string) ([]byte, error) {
	if c.tsbClient.Config.Key.RSAPublicKey == "" {
		c.tsbClient.Config.Key.RSALabel = c.keyLabel
		c.tsbClient.getPublicKeyFromHSM(c.keyLabel, c.keyPassword)
	}
	encryptedData := c.tsbClient.EncryptData([]byte(plaintext), c.tsbClient.Config.Key.RSAPublicKey)
	return []byte(fmt.Sprintf("securosys:%s:%s:%s", "v1", encryptedData.EncryptedText, encryptedData.Vector)), nil
}

func (c *SecurosysHSMClient) Decrypt(encryptedPayload string, keyVersion string, initializationVector string) ([]byte, error) {
	c.tsbClient.Config.Key.RSALabel = c.keyLabel
	key, err, _ := c.tsbClient.GetKeyAttributes(c.keyLabel, c.keyPassword)
	if err != nil {
		return nil, err
	}
	c.tsbClient.Config.Key.KeyAttributes = key

	if len(key.Policy.RuleUse.Tokens) > 0 {
		for _, token := range key.Policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				str := c.tsbClient.DecryptDataWithPolicy([]byte(encryptedPayload), initializationVector, c.keyLabel, c.keyPassword)
				return []byte(str), nil
			}
		}
	}
	str := c.tsbClient.DecryptData([]byte(encryptedPayload), initializationVector, c.keyLabel, c.keyPassword)

	return []byte(str), nil
}
