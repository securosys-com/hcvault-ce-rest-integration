// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
)

func comparePublicKey(sc *storageContext, key *keyEntry, publicKey crypto.PublicKey) (bool, error) {
	var publicKeyForKeyEntry crypto.PublicKey
	if key.PrivateKeyType != certutil.UnknownPrivateKey {
		founded, err := getPublicKey(sc.Context, sc.Backend, key)
		if err != nil {
			return false, err
		}
		publicKeyForKeyEntry = founded
	} else {
		publicKeyForKeyEntry = key.getPublicKey()
		if publicKeyForKeyEntry == nil {
			return false, nil
		}
	}

	return certutil.ComparePublicKeysAndType(publicKeyForKeyEntry, publicKey)
}

func getPublicKey(ctx context.Context, b *backend, key *keyEntry) (crypto.PublicKey, error) {
	if key.PublicKey != "" {
		return ParsePublicKeyString(key.PublicKey), nil
	}
	if key.PrivateKeyType == certutil.ManagedPrivateKey {
		keyId, err := extractManagedKeyId([]byte(key.PrivateKey))
		if err != nil {
			return nil, err
		}
		return getManagedKeyPublicKey(ctx, b, keyId)
	}

	signer, _, _, err := getSignerFromKeyEntryBytes(key)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

func getSignerFromKeyEntryBytes(key *keyEntry) (crypto.Signer, certutil.BlockType, *pem.Block, error) {
	// if key.PrivateKeyType == certutil.UnknownPrivateKey {
	// 	return nil, certutil.UnknownBlock, nil, errutil.InternalError{Err: fmt.Sprintf("unsupported unknown private key type for key: %s (%s)", key.ID, key.Name)}
	// }

	if key.PrivateKeyType == certutil.ManagedPrivateKey {
		return nil, certutil.UnknownBlock, nil, errutil.InternalError{Err: fmt.Sprintf("can not get a signer from a managed key: %s (%s)", key.ID, key.Name)}
	}

	bytes, blockType, blk, err := getSignerFromBytes([]byte(key.PrivateKey))
	if err != nil {
		return nil, certutil.UnknownBlock, nil, errutil.InternalError{Err: fmt.Sprintf("failed parsing key entry bytes for key id: %s (%s): %s", key.ID, key.Name, err.Error())}
	}

	return bytes, blockType, blk, nil
}

func getSignerFromBytes(keyBytes []byte) (crypto.Signer, certutil.BlockType, *pem.Block, error) {
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, certutil.UnknownBlock, pemBlock, errutil.InternalError{Err: "no data found in PEM block"}
	}

	signer, blk, err := certutil.ParseDERKey(pemBlock.Bytes)
	if err != nil {
		return nil, certutil.UnknownBlock, pemBlock, errutil.InternalError{Err: fmt.Sprintf("failed to parse PEM block: %s", err.Error())}
	}
	return signer, blk, pemBlock, nil
}

func getPublicKeyFromBytes(keyBytes []byte) (crypto.PublicKey, error) {
	signer, _, _, err := getSignerFromBytes(keyBytes)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("failed parsing key bytes: %s", err.Error())}
	}

	return signer.Public(), nil
}

func importKeyFromBytes(sc *storageContext, keyValue string, keyName string, externalKeyName string, importSecurosysHSM bool, extractable bool) (*keyEntry, bool, error) {
	signer, _, _, err := getSignerFromBytes([]byte(keyValue))
	if err != nil {
		return nil, false, err
	}
	privateKeyType := certutil.GetPrivateKeyTypeFromSigner(signer)
	if privateKeyType == certutil.UnknownPrivateKey {
		return nil, false, errors.New("unsupported private key type within pem bundle")
	}
	if importSecurosysHSM {
		pub := signer.Public()
		bytes, _ := x509.MarshalPKIXPublicKey(pub)
		publicKeyPEM := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bytes,
		}
		bytes, _ = x509.MarshalPKCS8PrivateKey(signer)
		privateKeyPEM := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		}
		publicPemString := pem.EncodeToMemory(publicKeyPEM)
		privatePemString := pem.EncodeToMemory(privateKeyPEM)
		client, err := NewSecurosysHSMClient(nil)
		if err != nil {
			return nil, false, err
		}
		_, err = client.ImportKey(externalKeyName, string(privateKeyType), client.CleanUpHeadersAndNewLines(string(privatePemString)), client.CleanUpHeadersAndNewLines(string(publicPemString)), extractable)
		if err != nil {
			return nil, false, err
		}
		key, existed, err := sc.importKeyWithoutPrivateKey(externalKeyName, client.CleanUpHeadersAndNewLines(string(publicPemString)), keyName, "securosys-hsm")
		if err != nil {
			return nil, false, err
		}
		return key, existed, nil
	} else {
		key, existed, err := sc.importKey(keyValue, keyName, privateKeyType)
		if err != nil {
			return nil, false, err
		}
		return key, existed, nil

	}
}
