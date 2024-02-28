// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mock

import (
	"context"
	"os"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const MockPluginVersionEnv = "TESTING_MOCK_VAULT_PLUGIN_VERSION"

// New returns a new backend as an interface. This func
// is only necessary for builtin backend plugins.
func New() (interface{}, error) {
	return Backend(), nil
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// FactoryType is a wrapper func that allows the Factory func to specify
// the backend type for the mock backend plugin instance.
func FactoryType(backendType logical.BackendType) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		b := Backend()
		b.BackendType = backendType
		if err := b.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// Backend returns a private embedded struct of framework.Backend.
func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: "",
		Paths: framework.PathAppend(
			errorPaths(&b),
			kvPaths(&b),
			[]*framework.Path{
				pathInternal(&b),
				pathSpecial(&b),
				pathRaw(&b),
			},
		),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"special",
			},
		},
		Secrets:     []*framework.Secret{},
		Invalidate:  b.invalidate,
		BackendType: logical.TypeLogical,
	}
	b.internal = "bar"
	b.RunningVersion = "v0.0.0+mock"
	if version := os.Getenv(MockPluginVersionEnv); version != "" {
		b.RunningVersion = version
	}
	return &b
}

type backend struct {
	*framework.Backend

	// internal is used to test invalidate
	internal string
}

func (b *backend) invalidate(ctx context.Context, key string) {
	switch key {
	case "internal":
		b.internal = ""
	}
}
