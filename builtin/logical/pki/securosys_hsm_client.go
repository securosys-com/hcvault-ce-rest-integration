/*
Copyright (c) 2024 Securosys SA, authors: Tomasz Madej

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
package pki

import (
	"crypto/x509"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	api "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
)

type SecurosysHSMClient struct {
	Client           *api.Client
	SecretEnginePath string
	SecretEngine     *api.MountOutput
	logger           hclog.Logger
}

var hsmClient *SecurosysHSMClient = nil

func (hsm *SecurosysHSMClient) PrintErrorLogs(err error) error {
	hsm.logger.Error(err.Error())
	return err
}
func NewSecurosysHSMClient(req *logical.Request) (*SecurosysHSMClient, error) {
	if hsmClient != nil {
		return hsmClient, nil
	}
	hsmClient = &SecurosysHSMClient{logger: hclog.New(&hclog.LoggerOptions{
		Name: fmt.Sprintf("pki-securosys-hsm-client")})}
	if req == nil {
		return nil, hsmClient.PrintErrorLogs(errors.New("request is nil"))
	}
	clientConfig := api.DefaultConfig()
	client, _ := api.NewClient(clientConfig)
	client.SetToken(req.ClientTokenOrig)

	if req.Connection == nil {
		return nil, nil
	}
	if v := os.Getenv(api.EnvVaultAddress); v != "" {
		client.SetAddress(v)
	} else {
		if req.Connection.ConnState == nil {
			hsmClient.logger.Info(fmt.Sprintf("Use address to connect HC Vault: %s", "http://"+req.Host))
			client.SetAddress("http://" + req.Host)

		} else {
			hsmClient.logger.Info(fmt.Sprintf("Use address to connect HC Vault: %s", "https://"+req.Host))
			client.SetAddress("https://" + req.Host)
		}
	}
	hsmClient.Client = client
	isEnabled, path, secret, err := hsmClient.isSecretEnabled()
	if isEnabled {
		hsmClient.SecretEnginePath = path
		hsmClient.SecretEngine = secret
	} else {
		return nil, hsmClient.PrintErrorLogs(err)
	}
	err = hsmClient.checkConnection()
	if err != nil {
		return nil, hsmClient.PrintErrorLogs(err)
	}
	return hsmClient, nil
}

func (hsm *SecurosysHSMClient) isSecretEnabled() (bool, string, *api.MountOutput, error) {
	mounts, err := hsm.Client.Sys().ListMounts()
	if err != nil {
		return false, "", nil, err
	}
	for path, secret := range mounts {
		if secret.Type == "securosys-hsm" {
			secretJson, _ := json.Marshal(secret)
			hsmClient.logger.Info(fmt.Sprintf("Found enabled securosys-hsm plugin: %s", string(secretJson)))
			return true, path, secret, nil
		}

	}

	return false, "", nil, fmt.Errorf("securosys-hsm secret engine not found or is not enabled")
}
func (hsm *SecurosysHSMClient) checkConnection() error {
	response, err := hsm.Client.Logical().Read(hsm.SecretEnginePath + "config")
	if err != nil {
		return err
	}
	if response.Data["restapi"] == "" {
		return fmt.Errorf("securosys-hsm plugin is not configured correctly")
	}
	hsmClient.logger.Info(fmt.Sprintf("securosys-hsm plugin is configured correctly: %s", response.Data["restapi"]))
	return nil

}
func (hsm *SecurosysHSMClient) mapEcKeyBits(keyBits int) string {
	switch keyBits {
	case 224:
		return "1.3.132.0.33"
	case 256:
		return "1.2.840.10045.3.1.7"
	case 384:
		return "1.3.132.0.34"
	case 521:
		return "1.3.132.0.35"
	}
	return ""
}
func (hsm *SecurosysHSMClient) mapEdKeyBits(keyBits int) string {
	switch keyBits {
	case 0:
		return "1.3.6.1.4.1.11591.15.1"
	}
	return ""
}
func (hsm *SecurosysHSMClient) mapKey(keyType string, keyBits int) (string, string) {
	switch strings.ToLower(keyType) {
	case "rsa":
		return "rsa", strconv.Itoa(keyBits)
	case "ec":
		return "ec", hsm.mapEcKeyBits(keyBits)
	case "ed25519":
		return "ed", hsm.mapEdKeyBits(keyBits)
	}
	return "rsa", "4096"
}
func (hsm *SecurosysHSMClient) CleanUpHeadersAndNewLines(pem string) string {
	result := strings.ReplaceAll(pem, "\n", "")
	result = strings.ReplaceAll(result, "-----BEGIN PUBLIC KEY-----", "")
	result = strings.ReplaceAll(result, "-----BEGIN PRIVATE KEY-----", "")
	result = strings.ReplaceAll(result, "-----END PUBLIC KEY-----", "")
	result = strings.ReplaceAll(result, "-----END PRIVATE KEY-----", "")
	return result
}
func (hsm *SecurosysHSMClient) CreateKeyIfNotExists(tsbKeyLabel string, keyType string, keyBits int, extractable bool) (map[string]interface{}, error) {

	algorithm, bits := hsm.mapKey(keyType, keyBits)
	response, err := hsm.Client.Logical().Read(hsm.SecretEnginePath + "keys/" + tsbKeyLabel)
	if err == nil {
		attributes := response.Data["attributes"].(map[string]interface{})
		if attributes["sign"] == false {
			return nil, hsmClient.PrintErrorLogs(fmt.Errorf("Key attribute 'sign' is false. Please use another key."))
		}

		if response.Data["algorithm"].(string) != strings.ToUpper(algorithm) {
			return nil, hsmClient.PrintErrorLogs(fmt.Errorf("Key algorithm not match requested one. Expected '%s' got '%s'. Please use another key.", algorithm, response.Data["algorithm"].(string)))
		}
		return response.Data, nil

	}
	response, err = hsm.Client.Logical().Write(hsm.SecretEnginePath+"keys/"+tsbKeyLabel+"/register", map[string]interface{}{
		"keyLabel": tsbKeyLabel,
	})
	if err == nil {
		response, err := hsm.Client.Logical().Read(hsm.SecretEnginePath + "keys/" + tsbKeyLabel)
		if err == nil {
			attributes := response.Data["attributes"].(map[string]interface{})
			if attributes["sign"] == false {
				return nil, hsmClient.PrintErrorLogs(fmt.Errorf("Key attribute 'sign' is false. Please use another key."))
			}

			if response.Data["algorithm"].(string) != strings.ToUpper(algorithm) {
				return nil, hsmClient.PrintErrorLogs(fmt.Errorf("Key algorithm not match requested one. Expected '%s' got '%s'. Please use another key.", algorithm, response.Data["algorithm"].(string)))
			}
			return response.Data, nil

		}

	} else {

		attributes := `{"decrypt": false,"sign": true,"unwrap": false,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`
		if extractable {
			attributes = `{"decrypt": false,"sign": true,"unwrap": false,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`
		}
		if algorithm == "rsa" {
			response, err := hsm.Client.Logical().Write(hsm.SecretEnginePath+"keys/"+algorithm+"/"+tsbKeyLabel, map[string]interface{}{
				"keyLabel":   tsbKeyLabel,
				"keySize":    bits,
				"attributes": attributes,
			})
			if err != nil {
				return nil, hsmClient.PrintErrorLogs(err)
			}
			return response.Data, nil
		} else {
			response, err := hsm.Client.Logical().Write(hsm.SecretEnginePath+"keys/"+algorithm+"/"+tsbKeyLabel, map[string]interface{}{
				"keyLabel":   tsbKeyLabel,
				"curveOid":   bits,
				"attributes": attributes,
			})
			if err != nil {
				return nil, hsmClient.PrintErrorLogs(err)
			}
			return response.Data, nil

		}
	}

	return nil, hsmClient.PrintErrorLogs(err)
}
func (hsm *SecurosysHSMClient) ImportKey(tsbKeyLabel string, keyType string, privateKey string, publicKey string, extractable bool) (map[string]interface{}, error) {
	algorithm := strings.ToUpper(keyType)
	attributes := `{"decrypt": false,"sign": true,"unwrap": false,"derive": true,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`
	if extractable {
		attributes = `{"decrypt": false,"sign": true,"unwrap": false,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`
	}
	response, err := hsm.Client.Logical().Write(hsm.SecretEnginePath+"keys/"+tsbKeyLabel+"/import", map[string]interface{}{
		"keyLabel":   tsbKeyLabel,
		"algorithm":  algorithm,
		"privateKey": privateKey,
		"publicKey":  publicKey,
		"attributes": attributes,
	})
	if err != nil {
		return nil, hsmClient.PrintErrorLogs(err)
	}
	return response.Data, nil

}
func (hsm *SecurosysHSMClient) GetKey(tsbKeyLabel string) (map[string]interface{}, error) {
	response, err := hsm.Client.Logical().Read(hsm.SecretEnginePath + "keys/" + tsbKeyLabel)
	if err == nil {
		return response.Data, nil

	}
	return nil, err
}
func (hsm *SecurosysHSMClient) ExportKey(tsbKeyLabel string) (map[string]interface{}, error) {
	keyResponse, err := hsm.GetKey(tsbKeyLabel)
	if err == nil {
		attributes := keyResponse["attributes"].(map[string]interface{})
		if attributes["extractable"] == false {
			return nil, hsmClient.PrintErrorLogs(fmt.Errorf("Key attribute 'extractable' is false. Cannot export key as private key pem."))
		}
		if keyResponse["privateKey"] != nil {
			return keyResponse, nil
		}
		response, err := hsm.Client.Logical().Write(hsm.SecretEnginePath+"keys/"+tsbKeyLabel+"/export", map[string]interface{}{})
		if err == nil {
			return response.Data, nil

		}
	}
	return nil, err
}
func (hsm *SecurosysHSMClient) mapSignatureAlgorithm(signAlgorithm x509.SignatureAlgorithm) string {
	switch signAlgorithm {
	case x509.SHA256WithRSA:
		return "SHA256_WITH_RSA"
	case x509.SHA384WithRSA:
		return "SHA384_WITH_RSA"
	case x509.SHA512WithRSA:
		return "SHA512_WITH_RSA"
	case x509.SHA256WithRSAPSS:
		return "SHA256_WITH_RSA_PSS"
	case x509.SHA384WithRSAPSS:
		return "SHA384_WITH_RSA_PSS"
	case x509.SHA512WithRSAPSS:
		return "SHA512_WITH_RSA_PSS"
	case x509.ECDSAWithSHA256:
		return "SHA256_WITH_ECDSA"
	case x509.ECDSAWithSHA384:
		return "SHA384_WITH_ECDSA"
	case x509.ECDSAWithSHA512:
		return "SHA512_WITH_ECDSA"
	case x509.ECDSAWithSHA1:
		return "SHA1_WITH_ECDSA"
	case x509.PureEd25519:
		return "EDDSA"
	}
	return ""
}
func (hsm *SecurosysHSMClient) GetApproverNames(approvers map[string]interface{}) string {
	approverNames := make([]string, 0, len(approvers))

	for k := range approvers {
		approverNames = append(approverNames, k)
	}
	approverNamesString, _ := json.Marshal(approverNames)
	return string(approverNamesString[:])

}
func (hsm *SecurosysHSMClient) Sign(keyName string, tsbKeyLabel string, toSign []byte, signAlgorithm x509.SignatureAlgorithm, additionalMetaData map[string]string) ([]byte, error) {
	addJson, _ := json.Marshal(additionalMetaData)
	response, err := hsm.Client.Logical().Write(hsm.SecretEnginePath+"operation/sign/"+tsbKeyLabel, map[string]interface{}{
		"signatureAlgorithm": hsm.mapSignatureAlgorithm(signAlgorithm),
		"payload":            b64.StdEncoding.EncodeToString(toSign),
		"additionalMetaData": string(addJson[:]),
	})
	if err != nil {
		return nil, hsmClient.PrintErrorLogs(err)
	}
	if response.Data["signature"] == nil {
		requestId := response.Data["id"].(string)
		finished := false
		limit := 300
		oldList := ""
		hsmClient.logger.Info(fmt.Sprintf("Sign operation using %s needs approval for request from: %s", keyName, hsmClient.GetApproverNames(response.Data["notYetApprovedBy"].(map[string]interface{}))))
		for finished == false {
			time.Sleep(1 * time.Second)
			response, err = hsm.Client.Logical().Read(hsm.SecretEnginePath + "requests/" + requestId)
			if oldList != hsmClient.GetApproverNames(response.Data["notYetApprovedBy"].(map[string]interface{})) && len(response.Data["notYetApprovedBy"].(map[string]interface{})) > 0 {
				hsmClient.logger.Info(fmt.Sprintf("Still waiting for approval from %s", hsmClient.GetApproverNames(response.Data["notYetApprovedBy"].(map[string]interface{}))))
				oldList = hsmClient.GetApproverNames(response.Data["notYetApprovedBy"].(map[string]interface{}))
			}
			if response.Data["status"].(string) != "PENDING" {
				finished = true
			}
			limit--
			if limit <= 0 {
				return nil, hsmClient.PrintErrorLogs(fmt.Errorf("Exceed 300s limit for approval"))
			}
		}
		hsmClient.logger.Info("All approvals collected!")
		data, err := base64.StdEncoding.DecodeString(response.Data["result"].(string))
		if err != nil {
			return nil, hsmClient.PrintErrorLogs(err)
		}
		additionalMetaDataJson, _ := json.Marshal(additionalMetaData)
		hsmClient.logger.Info(fmt.Sprintf("Signed certificate [%s] using key %s", additionalMetaDataJson, keyName))

		return data, nil
	} else {
		additionalMetaDataJson, _ := json.Marshal(additionalMetaData)
		hsmClient.logger.Info(fmt.Sprintf("Signed certificate [%s] using key %s", additionalMetaDataJson, keyName))
		data, err := base64.StdEncoding.DecodeString(response.Data["signature"].(string))
		if err != nil {
			return nil, hsmClient.PrintErrorLogs(err)
		}

		return data, nil
	}
}
