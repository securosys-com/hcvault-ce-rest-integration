/*
Copyright (c) 2024 Securosys SA, authors: Tomasz Madej
This work is licensed under the terms of the GNU Lesser General Public License license.

See terms of license at gnu.org.

This work is free software; you can redistribute it and/or modify it under the terms of the 
GNU Lesser General Public License as published by the Free Software Foundation; 
either version 2.1 of the license, or (at your option) any later version. 
This work is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

//go:build !enterprise

package pki

import (
	"context"
	"crypto"
	"errors"
	"io"

	"github.com/hashicorp/vault/sdk/helper/certutil"
)

var errEntOnly = errors.New("managed keys are supported within enterprise edition only")

func generateManagedKeyCABundle(ctx context.Context, b *backend, keyId managedKeyId, data *certutil.CreationBundle, randomSource io.Reader) (bundle *certutil.ParsedCertBundle, err error) {
	return nil, errEntOnly
}

func generateManagedKeyCSRBundle(ctx context.Context, b *backend, keyId managedKeyId, data *certutil.CreationBundle, addBasicConstraints bool, randomSource io.Reader) (bundle *certutil.ParsedCSRBundle, err error) {
	return nil, errEntOnly
}

func getManagedKeyPublicKey(ctx context.Context, b *backend, keyId managedKeyId) (crypto.PublicKey, error) {
	return nil, errEntOnly
}

func parseManagedKeyCABundle(ctx context.Context, b *backend, bundle *certutil.CertBundle) (*certutil.ParsedCertBundle, error) {
	return nil, errEntOnly
}

func extractManagedKeyId(privateKeyBytes []byte) (UUIDKey, error) {
	return "", errEntOnly
}

func createKmsKeyBundle(ctx context.Context, b *backend, keyId managedKeyId) (certutil.KeyBundle, certutil.PrivateKeyType, error) {
	return certutil.KeyBundle{}, certutil.UnknownPrivateKey, errEntOnly
}
func createSecurosysHsmKeyBundle(ctx context.Context, b *backend, keyId managedKeyId) (certutil.KeyBundle, certutil.PrivateKeyType, error) {
	return certutil.KeyBundle{}, certutil.UnknownPrivateKey, nil
}

func getManagedKeyInfo(ctx context.Context, b *backend, keyId managedKeyId) (*managedKeyInfo, error) {
	return nil, errEntOnly
}
