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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type key struct {
	Label     string
	PublicKey string
}
type request struct {
	Id    string
	Label string
}
type EncryptedData struct {
	EncryptedText string
	Vector        string
}

type TSBClient struct {
	Config *Configurations
}

// This is the function thats makes request to SecurosysHSM
func (tsb *TSBClient) TSBCall(apiKeyName string, method string, path string, jsonData []byte) ([]byte, int, error) {
	compactBody := &bytes.Buffer{}
	compactResponseBody := &bytes.Buffer{}
	if Debug == true {
		logger.Info("=======================================================")
		logger.Info("NEW REQUEST:")
		logger.Info("METHOD: " + method)
		logger.Info("URL: " + tsb.Config.Settings.RestApi + path)
		json.Compact(compactBody, jsonData)
		logger.Info("BODY: " + compactBody.String())
	}
	req, err := http.NewRequest(method, tsb.Config.Settings.RestApi+path, bytes.NewBuffer(jsonData))
	if tsb.Config.Settings.Auth == TOKEN {
		req.Header.Set("Authorization", "Bearer "+tsb.Config.Settings.BearerToken)
	}
	req.Header.Set("Content-Type", "application/json")
	canGetApiKey, err := tsb.CanGetNewApiKeyByName(apiKeyName)
	if err != nil {
		return []byte(fmt.Sprintf("All apikeys in group %s are invalid", apiKeyName)), 401, fmt.Errorf("status: %d, body: All apikeys in group %s are invalid", 401, apiKeyName)
	}
	if canGetApiKey {
		req.Header.Set("X-API-KEY", *tsb.GetApiKeyByName(apiKeyName))
	}

	client := &http.Client{}
	if tsb.Config.Settings.Auth == CERT {

		caCert, _ := os.ReadFile(tsb.Config.Settings.CertPath)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		clientTLSCert, err := tls.LoadX509KeyPair(tsb.Config.Settings.CertPath, tsb.Config.Settings.KeyPath)
		if err != nil {
			log.Fatalf("Error loading certificate and key file: %v", err)
			return nil, 0, err
		}

		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{clientTLSCert},
			},
		}

	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 500, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if canGetApiKey && resp.StatusCode == http.StatusUnauthorized {
		var result map[string]interface{}
		json.Unmarshal(body, &result)
		errorCode := result["errorCode"].(float64)

		if errorCode == 631 {
			tsb.RollOverApiKey(apiKeyName)
			return tsb.TSBCall(apiKeyName, method, path, jsonData)

		}
	}
	if Debug == true {
		logger.Info("\n")
		logger.Info("RESPONSE:")
		logger.Info("CODE: " + strconv.Itoa(resp.StatusCode))
		json.Compact(compactResponseBody, body)
		logger.Info("DATA: " + compactResponseBody.String())
		logger.Info("=======================================================")
		logger.Info("\n")
	}

	return body, resp.StatusCode, err
}
func (tsb *TSBClient) RollOverApiKey(name string) error {
	switch name {
	case "KeyManagementToken":
		tsb.Config.Settings.CurrentApiKeyTypeIndex.KeyManagementTokenIndex += 1
		return nil
	case "KeyOperationToken":
		if len(tsb.Config.Settings.ApiKeys.KeyOperationToken) == 0 {
			return fmt.Errorf("no KeyOperationToken provided")
		}
		tsb.Config.Settings.CurrentApiKeyTypeIndex.KeyOperationTokenIndex += 1
		return nil
	case "ApproverToken":
		if len(tsb.Config.Settings.ApiKeys.ApproverToken) == 0 {
			return fmt.Errorf("no ApproverToken provided")
		}
		tsb.Config.Settings.CurrentApiKeyTypeIndex.ApproverTokenIndex += 1
		return nil
	case "ServiceToken":
		if len(tsb.Config.Settings.ApiKeys.ServiceToken) == 0 {
			return fmt.Errorf("no ServiceToken provided")
		}
		tsb.Config.Settings.CurrentApiKeyTypeIndex.ServiceTokenIndex += 1
		return nil
	case "ApproverKeyManagementToken":
		if len(tsb.Config.Settings.ApiKeys.ApproverKeyManagementToken) == 0 {
			return fmt.Errorf("no ApproverKeyManagementToken provided")
		}
		tsb.Config.Settings.CurrentApiKeyTypeIndex.ApproverKeyManagementTokenIndex += 1
		return nil
	}
	return fmt.Errorf("apikey usign name %s does not exist", name)

}

func (tsb *TSBClient) CanGetNewApiKeyByName(name string) (bool, error) {
	switch name {
	case "KeyManagementToken":
		if len(tsb.Config.Settings.ApiKeys.KeyManagementToken) == 0 {
			return false, nil
		}
		if len(tsb.Config.Settings.ApiKeys.KeyManagementToken) > tsb.Config.Settings.CurrentApiKeyTypeIndex.KeyManagementTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	case "KeyOperationToken":
		if len(tsb.Config.Settings.ApiKeys.KeyOperationToken) == 0 {
			return false, nil
		}
		if len(tsb.Config.Settings.ApiKeys.KeyOperationToken) > tsb.Config.Settings.CurrentApiKeyTypeIndex.KeyOperationTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	case "ApproverToken":
		if len(tsb.Config.Settings.ApiKeys.ApproverToken) == 0 {
			return false, nil
		}
		if len(tsb.Config.Settings.ApiKeys.ApproverToken) > tsb.Config.Settings.CurrentApiKeyTypeIndex.ApproverTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	case "ServiceToken":
		if len(tsb.Config.Settings.ApiKeys.ServiceToken) == 0 {
			return false, nil
		}
		if len(tsb.Config.Settings.ApiKeys.ServiceToken) > tsb.Config.Settings.CurrentApiKeyTypeIndex.ServiceTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	case "ApproverKeyManagementToken":
		if len(tsb.Config.Settings.ApiKeys.ApproverKeyManagementToken) == 0 {
			return false, nil
		}
		if len(tsb.Config.Settings.ApiKeys.ApproverKeyManagementToken) > tsb.Config.Settings.CurrentApiKeyTypeIndex.ApproverKeyManagementTokenIndex {
			return true, nil
		}
		return false, fmt.Errorf("no more apikeys")
	}
	return false, fmt.Errorf("no apikey exists usign name %s", name)

}

func (tsb *TSBClient) GetApiKeyByName(name string) *string {
	switch name {
	case "KeyManagementToken":
		return &tsb.Config.Settings.ApiKeys.KeyManagementToken[tsb.Config.Settings.CurrentApiKeyTypeIndex.KeyManagementTokenIndex]
	case "KeyOperationToken":
		return &tsb.Config.Settings.ApiKeys.KeyOperationToken[tsb.Config.Settings.CurrentApiKeyTypeIndex.KeyOperationTokenIndex]
	case "ApproverToken":
		return &tsb.Config.Settings.ApiKeys.ApproverToken[tsb.Config.Settings.CurrentApiKeyTypeIndex.ApproverTokenIndex]
	case "ServiceToken":
		return &tsb.Config.Settings.ApiKeys.ServiceToken[tsb.Config.Settings.CurrentApiKeyTypeIndex.ServiceTokenIndex]
	case "ApproverKeyManagementToken":
		return &tsb.Config.Settings.ApiKeys.ApproverKeyManagementToken[tsb.Config.Settings.CurrentApiKeyTypeIndex.ApproverKeyManagementTokenIndex]
	}
	return nil
}

func (tsb *TSBClient) CheckConnection() (string, error) {
	logger.Info("Checking connection with TSB")
	body, code, errReq := tsb.TSBCall(ServiceTokenName, "GET", "/v1/keystore/statistics", nil)
	if code != 200 {
		logger.Error("TSB connection: fail")
		if errReq != nil {
			return string(body[:]), errReq
		} else {
			return string(body[:]), fmt.Errorf(string(body[:]))
		}

	}
	logger.Info("TSB connection: ok")
	return string(body[:]), nil
}

// This function preparing requests for synchronous decrypt
func (tsb *TSBClient) synchronousDecrypt(encryptedPayload string, decryptKeyName string, vector interface{}, cipherAlgorithm string, password string) (map[string]interface{}, int) {
	charsPasswordJson, _ := json.Marshal(StringToCharArray(password))
	vectorAttr := `"initializationVector":null`
	if vector != nil && vector != "" {
		vectorAttr = `"initializationVector":"` + vector.(string) + `"`
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`
	}
	jsonStr := []byte(`{"decryptRequest": {
		` + passwordString + `
		"encryptedPayload": "` + encryptedPayload + `",
		"decryptKeyName": "` + decryptKeyName + `",
		"cipherAlgorithm": "` + cipherAlgorithm + `",
		` + vectorAttr + `
		}}`)
	body, code, _ := tsb.TSBCall(KeyOperationTokenName, "POST", "/v1/synchronousDecrypt", jsonStr)
	var response interface{}
	json.Unmarshal(body, &response)
	data := response.(map[string]interface{})
	return data, code
}

// This function preparing requests for decrypt with approvals
func (tsb *TSBClient) decrypt(encryptedPayload string, decryptKeyName string, vector interface{}, cipherAlgorithm string, password string) string {
	charsPasswordJson, _ := json.Marshal(StringToCharArray(password))
	vectorAttr := `"initializationVector":null`
	if vector != nil && vector != "" {
		vectorAttr = `"initializationVector":"` + vector.(string) + `"`
	}
	var additionalMetaDataInfo map[string]string = make(map[string]string)
	metaDataB64, metaDataSignature, err := tsb.PrepareMetaData("Decrypt", additionalMetaDataInfo, map[string]string{})
	if err != nil {
		return ""
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`
	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{
		"encryptedPayload": "` + encryptedPayload + `",
		"decryptKeyName": "` + decryptKeyName + `",
		` + passwordString + `	
		"cipherAlgorithm": "` + cipherAlgorithm + `",
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `,
		` + vectorAttr + `
		}`
	var jsonStr = []byte(MinifyJson(`{
		"decryptRequest": ` + requestJson + `,
		"requestSignature":` + string(tsb.GenerateRequestSignature(requestJson)) + `

	  }`))
	body, _, _ := tsb.TSBCall(KeyOperationTokenName, "POST", "/v1/decrypt", jsonStr)
	var response interface{}
	json.Unmarshal(body, &response)
	data := response.(map[string]interface{})
	return data["decryptRequestId"].(string)
}

// This function converting byte to RSA.PublickKey
func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			Logs.UI.Error(err.Error())
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		Logs.UI.Error(err.Error())
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		Logs.UI.Error("not ok")
	}
	return key
}

// This function preparing requests for synchronous encrypt
func encrypt(payload string, publicKey string) (string, error) {
	secretMessage := []byte([]byte(payload))
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, BytesToPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\n"+publicKey+"\n-----END RSA PUBLIC KEY-----")), secretMessage, []byte(""))

	return b64.StdEncoding.EncodeToString(ciphertext), err
}

// This function getting approval name from PublicKey string
func (tsb *TSBClient) getApproverName(publicKey string) string {
	if len(tsb.Config.Key.KeyAttributes.Policy.RuleUse.Tokens) > 0 {
		for _, token := range tsb.Config.Key.KeyAttributes.Policy.RuleUse.Tokens {
			if len(token.Groups) > 0 {
				for _, group := range token.Groups {
					if len(group.Approvals) > 0 {
						for _, approval := range group.Approvals {
							if publicKey == *approval.Value {
								return *approval.Name
							}
							cert, err := ReadCertificate(*approval.Value)
							if err == nil {
								key := BytesToPublicKey([]byte("-----BEGIN RSA PUBLIC KEY-----\n" + publicKey + "\n-----END RSA PUBLIC KEY-----"))
								if cert.PublicKey.(*rsa.PublicKey).N.Cmp(key.N) == 0 && key.E == cert.PublicKey.(*rsa.PublicKey).E {
									return *approval.Name
								}
							}
						}
					}
				}
			}
		}
	}
	return ""
}
func ParsePublicKeyString(publicKey string) (crypto.PublicKey, error) {
	var pkForImportingKey crypto.PublicKey
	spkiBlock, _ := pem.Decode(WrapPublicKeyWithHeaders(publicKey))
	if spkiBlock == nil {
		return nil, fmt.Errorf("Cannot parse public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pkForImportingKey = pubInterface
	return pkForImportingKey, nil
}

// This function preparing Policy structure for generating SKA key requests
func preparePolicyTokens(policy map[string]string) string {
	var tokens []token
	var group group
	group.Name = "main"
	group.Quorum = len(policy)
	for name, element := range policy {
		var approval approval
		_, err := ReadCertificate(element)
		if err == nil {
			approval.TypeOfKey = "certificate"
			approval.Value = &element
		} else {
			_, err := ParsePublicKeyString(element)
			if err == nil {
				approval.TypeOfKey = "public_key"
				approval.Name = &name
				approval.Value = &element
			} else {
				approval.TypeOfKey = "onboarded_approver_certificate"
				approval.Name = &element
			}
		}
		group.Approvals = append(group.Approvals, approval)
	}

	var token token
	token.Name = "main"
	token.Timeout = 0
	token.Timelock = 0
	if len(policy) == 0 {
		token.Groups = nil
	} else {
		token.Groups = append(token.Groups, group)
	}
	tokens = append(tokens, token)
	json, _ := json.Marshal(tokens)
	return string(json)
}

// This function preparing requests for synchronous modify policy in key on Securosys HSM
func (tsb *TSBClient) ModifyRSA(label string, password string, approvalKeys map[string]string) (error, []byte, int) {
	charsPasswordJson, _ := json.Marshal(StringToCharArray(password))
	var policy string
	if approvalKeys == nil {
		approvalKeys = map[string]string{}
	}
	tokens := preparePolicyTokens(approvalKeys)
	policy = string(`
	,"policy":{
	  "ruleUse": {
		"tokens":` + tokens + `
	  }
	}`)
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`
	}

	jsonStr := []byte(`{
		"modifyRequest":{
			` + passwordString + `	
			"modifyKeyName": "` + label + `"
			` + policy + `}
		}`)
	body, code, err := tsb.TSBCall(KeyOperationTokenName, "POST", "/v1/synchronousModify", jsonStr)
	if code != 200 {
		return err, body, code
	}
	return nil, nil, code
}

// This function preparing requests for creating SKA key with/without policy
func (tsb *TSBClient) GenerateRSA(label string, password string, policy *Policy) ([]byte, int, error) {
	charsPasswordJson, _ := json.Marshal(StringToCharArray(password))

	policyJSON, err := policy.ToJSON()
	if err != nil {
		logger.Error(fmt.Sprintf("Cannot stringify policy. Error: %s\n", err.Error()))
		os.Exit(1)
	}
	policyString := string(`,"policy":` + string(policyJSON))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`
	}

	jsonStr := []byte(`{
	"label": "` + label + `",
	` + passwordString + `	
    "algorithm": "RSA",	
    "keySize": 2048,	
	"attributes": {
	"encrypt": false,
	"decrypt": true,
	"verify": false,
	"sign": true,
	"wrap": false,
	"unwrap": true,
	"derive": true,
	"bip32": false,
	"extractable": false,
	"modifiable": true,
	"destroyable": true,
	"sensitive": true
		}` + policyString + `}`)
	body, code, err := tsb.TSBCall(KeyManagementTokenName, "POST", "/v1/key", jsonStr)
	if err != nil {
		logger.Error(fmt.Sprintf("Cannot create a key '%s'. Error: %s\n", label, err.Error()))
		os.Exit(1)

	}
	if code != 201 {
		return body, code, err
	}
	return body, code, err
}

func (tsb *TSBClient) GetKeyAttributes(keyName string, password string) (KeyAttributes, error, int) {
	charsPasswordJson, _ := json.Marshal(StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"password": ` + string(charsPasswordJson) + `,`
	}
	jsonStr := []byte(`{
		` + passwordString + `
		"label":"` + keyName + `"
		}`)
	body, code, err := tsb.TSBCall(KeyManagementTokenName, "POST", "/v1/key/attributes", jsonStr)
	var key KeyAttributes
	if err != nil || code == 404 {
		return key, err, code
	}
	var response interface{}
	json.Unmarshal(body, &response)
	data := response.(map[string]interface{})
	jsonData := data["json"].(map[string]interface{})
	key.Algorithm = jsonData["algorithm"].(string)
	key.AlgorithmOid = jsonData["algorithmOid"].(string)
	key.CurveOid = ""
	if fmt.Sprintf("%T", jsonData["curveOid"]) == "string" {
		key.CurveOid = jsonData["curveOid"].(string)
	}
	key.Attributes = map[string]bool{}
	attributes := jsonData["attributes"].(map[string]interface{})
	for k, e := range attributes {
		if fmt.Sprintf("%T", e) == "bool" {
			key.Attributes[k] = e.(bool)
		}
	}
	if fmt.Sprintf("%T", jsonData["keySize"]) == "float64" {
		key.KeySize = jsonData["keySize"].(float64)
	}
	key.Xml = data["xml"].(string)
	key.XmlSignature = data["xmlSignature"].(string)
	key.AttestationKeyName = data["attestationKeyName"].(string)
	key.Label = jsonData["label"].(string)
	policyString, _ := json.Marshal(jsonData["policy"])
	json.Unmarshal(policyString, &key.Policy)
	if fmt.Sprintf("%T", jsonData["publicKey"]) == "string" {
		key.PublicKey = jsonData["publicKey"].(string)
	}

	return key, err, code
}

// This function preparing requests for removing Key from Securosys HSM
func (tsb *TSBClient) RemoveKey(keyName string) ([]byte, error, int) {
	{
		jsonStr := []byte(``)
		body, code, err := tsb.TSBCall(KeyManagementTokenName, "DELETE", "/v1/key/"+keyName, jsonStr)

		return body, err, code
	}
}

// This function encryptes data
func (tsb *TSBClient) EncryptData(data []byte, publicKey string) EncryptedData {
	encryptedText, _ := encrypt(string(data), publicKey)
	var encrypted EncryptedData

	encrypted.EncryptedText = encryptedText
	encrypted.Vector = ""
	return encrypted
}

// This function decrypt data without policy
func (tsb *TSBClient) DecryptData(data []byte, vector string, keyName string, keyPassword string) string {
	result, _ := tsb.synchronousDecrypt(string(data), keyName, vector, "RSA_PADDING_OAEP_WITH_SHA256", keyPassword)
	return result["payload"].(string)
}

// This function decrypt data with policy
func (tsb *TSBClient) DecryptDataWithPolicy(data []byte, vector string, keyName string, keyPassword string) string {
	requestId := tsb.decrypt(string(data), keyName, vector, "RSA_PADDING_OAEP_WITH_SHA256", keyPassword)
	var resp RequestResponse
	resp, _, _ = tsb.getRequest(requestId)
	start := time.Now()
	for resp.Status == "PENDING" {
		now := time.Now()
		if ShutdownTriggered {
			break
		}
		if now.Unix()-start.Unix() >= int64(tsb.Config.Settings.ApprovalTimeout) {
			Logs.UI.Error(fmt.Sprintf("Timeout for all approvals exceeded a %ss. Application will be closed. Vault remains sealed.", strconv.Itoa(tsb.Config.Settings.ApprovalTimeout)))
			os.Exit(1)
		}
		time.Sleep(time.Duration(tsb.Config.Settings.CheckEvery) * time.Second)
		resp, _, _ = tsb.getRequest(resp.Id)
	}
	if resp.Status == "REJECTED" {
		Logs.UI.Error(fmt.Sprintf("\nDecrypt operation is %s", resp.Status))
		Logs.UI.Error(fmt.Sprintf("Rejected by:"))
		for _, approver := range resp.RejectedBy {
			Logs.UI.Error(fmt.Sprintf("- %s\n", tsb.getApproverName(approver)))
		}
		Logs.UI.Error(fmt.Sprintf("Application will be closed. Vault remains sealed."))
		os.Exit(1)
	}
	return resp.Result
}

// This function preparing requests for getting information about approval for a task
func (tsb *TSBClient) getRequest(id string) (RequestResponse, error, int) {
	jsonStr := []byte(``)
	body, code, err := tsb.TSBCall(KeyOperationTokenName, "GET", "/v1/request/"+id, jsonStr)
	var requestResponse RequestResponse
	json.Unmarshal(body, &requestResponse)
	if len(requestResponse.NotYetApprovedBy) > 0 {
		logger.Info(fmt.Sprintf("Waiting for %d approval:", len(requestResponse.NotYetApprovedBy)))
	} else {
		logger.Info("All approval collected!")
	}
	for _, approver := range requestResponse.NotYetApprovedBy {
		logger.Info(fmt.Sprintf("- %s", tsb.getApproverName(approver)))
	}
	logger.Info("")

	return requestResponse, err, code
}

func (tsb *TSBClient) getPublicKeyFromHSM(keyLabel string, keyPassword string) error {
	if keyLabel != "" {
		key, err, code := tsb.GetKeyAttributes(keyLabel, keyPassword)
		if err != nil {
			return err
		}
		if code != 200 {
			return fmt.Errorf("Wrong HTTP Status code. Expected 200 got %d", code)
		}
		tsb.Config.Key.RSAPublicKey = key.PublicKey
		return nil
	} else {
		return nil
	}
}

// This function generates SKA on SecurosysHSM. This method also modifies config-hsm.yml and write information under Generated params
func (tsb *TSBClient) GenerateRSAKey(policy *Policy, keyLabel string, password string) (string, []byte, int, error) {
	body, code, err := tsb.GenerateRSA(keyLabel, password, policy)
	return keyLabel, body, code, err
}

// Function converts string into char array
func StringToCharArray(text string) []string {
	var array []string = make([]string, 0)
	for i := 0; i < len(text); i++ {
		array = append(array, string(text[i]))
	}
	return array
}

// Function preparing MetaData, which We are send with all asynchronous requests
func (tsb *TSBClient) PrepareMetaData(requestType string, additionalMetaData map[string]string, customMetaData map[string]string) (string, *string, error) {
	now := time.Now().UTC()
	var metaData map[string]string = make(map[string]string)
	metaData["time"] = fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
	metaData["app"] = "Hashicorp Vault"
	metaData["type"] = requestType
	for key, value := range additionalMetaData {
		metaData[key] = value
	}
	for key, value := range customMetaData {
		metaData[key] = value
	}
	metaJsonStr, errMarshal := json.Marshal(metaData)
	if errMarshal != nil {
		return "", nil, errMarshal
	}
	result, err := tsb.SignData(metaJsonStr)
	if err != nil {
		return b64.StdEncoding.EncodeToString(metaJsonStr),
			nil, nil

	}
	return b64.StdEncoding.EncodeToString(metaJsonStr),
		result, nil
}
func (tsb *TSBClient) SignData(dataToSign []byte) (*string, error) {
	if tsb.Config.Settings.ApplicationKeyPair.PrivateKey == nil || tsb.Config.Settings.ApplicationKeyPair.PublicKey == nil {
		return nil, fmt.Errorf("No Application Private Key or Public Key provided!")
	}
	h := sha256.New()
	h.Write(dataToSign)
	bs := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, tsb.GetApplicationPrivateKey(), crypto.SHA256, bs)
	if err != nil {
		return nil, err
	}
	result := b64.StdEncoding.EncodeToString(signature)
	return &result, nil
}
func (tsb *TSBClient) GetApplicationPrivateKey() *rsa.PrivateKey {
	if tsb.Config.Settings.ApplicationKeyPair.PrivateKey == nil {
		return nil
	}
	block, _ := pem.Decode(tsb.WrapPrivateKeyWithHeaders(false))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	if key == nil {
		block, _ = pem.Decode(tsb.WrapPrivateKeyWithHeaders(true))
		parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
		key := parseResult.(*rsa.PrivateKey)
		return key
	}
	return key
}

func (tsb *TSBClient) WrapPrivateKeyWithHeaders(pkcs8 bool) []byte {
	if tsb.Config.Settings.ApplicationKeyPair.PrivateKey == nil {
		return nil
	}
	if pkcs8 == false {
		return []byte("-----BEGIN RSA PRIVATE KEY-----\n" + *tsb.Config.Settings.ApplicationKeyPair.PrivateKey + "\n-----END RSA PRIVATE KEY-----")
	} else {
		return []byte("-----BEGIN PRIVATE KEY-----\n" + *tsb.Config.Settings.ApplicationKeyPair.PrivateKey + "\n-----END PRIVATE KEY-----")

	}

}
func (tsb *TSBClient) GenerateRequestSignature(requestData string) []byte {
	if tsb.Config.Settings.ApplicationKeyPair.PrivateKey == nil || tsb.Config.Settings.ApplicationKeyPair.PublicKey == nil {
		return []byte("null")
	}
	dst := &bytes.Buffer{}
	if err := json.Compact(dst, []byte(requestData)); err != nil {
		panic(err)
	}
	signature, _ := tsb.SignData([]byte(dst.String()))
	return []byte(`{
		"signature": "` + *signature + `",
		"digestAlgorithm": "SHA-256",
		"publicKey": "` + *tsb.Config.Settings.ApplicationKeyPair.PublicKey + `"
		}
	`)
}
func MinifyJson(requestData string) string {
	dst := &bytes.Buffer{}
	if err := json.Compact(dst, []byte(requestData)); err != nil {
		panic(err)
	}
	return dst.String()

}
