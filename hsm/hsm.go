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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
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
func (tsb *TSBClient) TSBCall(method string, path string, jsonData []byte) ([]byte, error, int) {
	compactBody := &bytes.Buffer{}
	compactResponseBody := &bytes.Buffer{}
	if Debug == true {
		Logs.UI.Info("=======================================================")
		Logs.UI.Info("NEW REQUEST:")
		Logs.UI.Info("METHOD: " + method)
		Logs.UI.Info("URL: " + tsb.Config.Settings.RestApi + path)
		json.Compact(compactBody, jsonData)
		Logs.UI.Info("BODY: " + compactBody.String())
	}
	req, err := http.NewRequest(method, tsb.Config.Settings.RestApi+path, bytes.NewBuffer(jsonData))
	if tsb.Config.Settings.Auth == TOKEN {
		req.Header.Set("Authorization", "Bearer "+tsb.Config.Settings.BearerToken)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	if tsb.Config.Settings.Auth == CERT {
		caCert, err := ioutil.ReadFile(tsb.Config.Settings.CertPath)
		if err != nil {
			Logs.UI.Error(err.Error())
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err, 500
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if Debug == true {
		Logs.UI.Info("\n")
		Logs.UI.Info("RESPONSE:")
		Logs.UI.Info("CODE: " + strconv.Itoa(resp.StatusCode))
		json.Compact(compactResponseBody, body)
		Logs.UI.Info("DATA: " + compactResponseBody.String())
		Logs.UI.Info("=======================================================")
		Logs.UI.Info("\n")
	}

	return body, err, resp.StatusCode
}

func (tsb *TSBClient) CheckConnection() (string, error) {
	Logs.UI.Info("Checking connection with TSB")
	body, errReq, code := tsb.TSBCall("GET", "/v1/keystore/statistics", nil)
	if code != 200 {
		Logs.UI.Info("TSB connection: fail")
		if errReq != nil {
			return string(body[:]), errReq
		} else {
			return string(body[:]), fmt.Errorf(string(body[:]))
		}

	}
	Logs.UI.Info("TSB connection: ok")
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
	body, _, code := tsb.TSBCall("POST", "/v1/synchronousDecrypt", jsonStr)
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
	now := time.Now()
	zone, _ := now.Zone()
	RunTimeInfo["time"] = fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d %s", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second(), zone)
	RunTimeInfo["app"] = "Hashicorp Vault"
	metaJsonStr, _ := json.Marshal(RunTimeInfo)
	h := sha256.New()
	h.Write(metaJsonStr)
	bs := h.Sum(nil)
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`
	}

	jsonStr := []byte(`{"decryptRequest": {
		"encryptedPayload": "` + encryptedPayload + `",
		"decryptKeyName": "` + decryptKeyName + `",
		` + passwordString + `	
		"cipherAlgorithm": "` + cipherAlgorithm + `",
		"metaData":"` + b64.StdEncoding.EncodeToString(metaJsonStr) + `",
		"metaDataSignature":"` + b64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(bs))) + `",
		` + vectorAttr + `
		}}`)
	body, _, _ := tsb.TSBCall("POST", "/v1/decrypt", jsonStr)
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
							if publicKey == approval.Value {
								return approval.Name
							}
						}
					}
				}
			}
		}
	}
	return ""
}

// This function preparing Policy structure for generating SKA key requests
func preparePolicyTokens(policy map[string]string) string {
	var tokens []token
	var group group
	group.Name = "main"
	group.Quorum = len(policy)
	for name, element := range policy {
		var approval approval
		approval.TypeOfKey = "public_key"
		approval.Name = name
		approval.Value = element
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
	body, err, code := tsb.TSBCall("POST", "/v1/synchronousModify", jsonStr)
	if code != 200 {
		return err, body, code
	}
	return nil, nil, code
}

// This function preparing requests for creating SKA key with/without policy
func (tsb *TSBClient) GenerateRSA(label string, password string, policy *Policy) (error, int) {
	charsPasswordJson, _ := json.Marshal(StringToCharArray(password))

	policyJSON, err := policy.ToJSON()
	if err != nil {
		fmt.Printf("Cannot stringify policy. Error: %s\n", err)
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
	_, err, code := tsb.TSBCall("POST", "/v1/key", jsonStr)
	if err != nil {
		fmt.Printf("Cannot create a key '%s'. Error: %s\n", label, err)
		os.Exit(1)

	}
	if code != 201 {
		return err, code
	}
	return nil, code
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
	body, err, code := tsb.TSBCall("POST", "/v1/key/attributes", jsonStr)
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
		body, err, code := tsb.TSBCall("DELETE", "/v1/key/"+keyName, jsonStr)

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
	body, err, code := tsb.TSBCall("GET", "/v1/request/"+id, jsonStr)
	var requestResponse RequestResponse
	json.Unmarshal(body, &requestResponse)
	if len(requestResponse.NotYetApprovedBy) > 0 {
		Logs.UI.Info(fmt.Sprintf("Waiting for %d approval:", len(requestResponse.NotYetApprovedBy)))
	} else {
		Logs.UI.Info("All approval collected!")
	}
	for _, approver := range requestResponse.NotYetApprovedBy {
		Logs.UI.Info(fmt.Sprintf("- %s", tsb.getApproverName(approver)))
	}
	Logs.UI.Info("")

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
func (tsb *TSBClient) GenerateRSAKey(policy *Policy, keyLabel string, password string) string {
	tsb.GenerateRSA(keyLabel, password, policy)
	return keyLabel
}

// Function converts string into char array
func StringToCharArray(text string) []string {
	var array []string = make([]string, 0)
	for i := 0; i < len(text); i++ {
		array = append(array, string(text[i]))
	}
	return array
}
