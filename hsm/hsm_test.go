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
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	serverConfig "github.com/hashicorp/vault/command/server"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/mitchellh/cli"
)

var (
	ui        *cli.MockUi
	configHCL *serverConfig.Config
	seal      *configutil.KMS
	tsbClient *TSBClient
)

func init() {
	ui = cli.NewMockUi()
	Logs.UI = ui
	configHCLPath := ""
	if os.Getenv("CONFIG_HCL_PATH") == "" {
		configHCLPath = "test_config.hcl"
	} else {
		configHCLPath = os.Getenv("CONFIG_HCL_PATH")
	}
	configHCL, err := serverConfig.LoadConfig(configHCLPath)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)

	}
	seal = configHCL.SharedConfig.Seals[0]

	config := InitConfig(true)
	config.Settings.RestApi = seal.Config["tsb_api_endpoint"]
	config.Settings.Auth = seal.Config["auth"]
	config.Settings.BearerToken = seal.Config["bearer_token"]
	config.Settings.CertPath = seal.Config["cert_path"]

	tsbClient = &TSBClient{
		Config: &config,
	}
}

func TestGenerateSKA(t *testing.T) {
	now := time.Now()
	label := "HASHICORP_VAULT_RSA_TEST_KEY_" + strconv.FormatInt(now.Unix(), 10)
	tsbClient.RemoveKey(label)
	keyLabel := tsbClient.GenerateRSAKey(nil, label, "")
	_, _, code := tsbClient.GetKeyAttributes(keyLabel, "")
	tsbClient.RemoveKey(label)
	if code != 200 {
		t.Fatalf("RSA key is not generated")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	now := time.Now()
	label := "HASHICORP_VAULT_RSA_TEST_KEY_" + strconv.FormatInt(now.Unix(), 10)
	original := "test"
	tsbClient.RemoveKey(label)
	keyLabel := tsbClient.GenerateRSAKey(nil, label, "")
	key, err, code := tsbClient.GetKeyAttributes(keyLabel, "")
	if code != 200 {
		t.Fatalf("RSA key is not generated")
	}
	//, TDEA_CBC_NO_PADDING
	encrypted := tsbClient.EncryptData([]byte(original), key.PublicKey)
	if err != nil {
		tsbClient.RemoveKey(label)
		t.Fatal(err)
		t.Fatalf("Text is not encrypted correctly")
	}

	decrypted, code := tsbClient.synchronousDecrypt(string(encrypted.EncryptedText), key.Label, encrypted.Vector, "RSA_PADDING_OAEP_WITH_SHA256", "")
	if code != 200 {
		tsbClient.RemoveKey(label)
		t.Fatalf("Text is not decrypted correctly")
	}
	decoded, _ := base64.StdEncoding.DecodeString(decrypted["payload"].(string))
	if string(decoded) != original {
		tsbClient.RemoveKey(label)
		t.Fatalf("Text is not decrypted correctly")
	}
	tsbClient.RemoveKey(label)
}
