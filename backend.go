package main

import (
	"context"
	"errors"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/ka-yamag/vault-plugin-auth-athenz/internal/athenz"
	"github.com/ka-yamag/vault-plugin-auth-athenz/internal/config"
)

const (
	backendHelp = `
The "athenz" credential provider allows authentication using Athenz.
`
	defaultConfigPath = "/etc/vault/plugin/athenz_plugin.yaml"
)

var confPath = ""

// SetConfigPath sets the config file path for athenz updator daemon
// func SetConfigPath(path string) {
//   confPath = path
// }

type athenzAuthBackend struct {
	*framework.Backend

	l *sync.RWMutex

	updaterCtx       context.Context
	updaterCtxCancel context.CancelFunc
}

// factory is used by framework
func factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	if p, ok := c.Config["--config-file"]; ok {
		confPath = p
	}
	if confPath == "" {
		return nil, errors.New("athenz config path not set")
	}

	b, err := backend()
	if err != nil {
		return nil, err
	}

	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() (*athenzAuthBackend, error) {
	var b athenzAuthBackend
	b.updaterCtx, b.updaterCtxCancel = context.WithCancel(context.Background())

	conf, err := config.NewConfig(confPath)
	if err != nil {
		return nil, err
	}

	if err := athenz.NewValidator(conf.Athenz); err != nil {
		return nil, err
	}

	// Initialize validator
	if err := athenz.GetValidator().Init(b.updaterCtx); err != nil {
		return nil, err
	}

	// Start validator
	athenz.GetValidator().Start(b.updaterCtx)

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeCredential,
		// AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfigClient(&b),
				pathLogin(&b),
				pathListClients(&b),
			},
		),
		Clean: b.cleanup,
	}

	b.l = &sync.RWMutex{}

	return &b, nil
}

func (b *athenzAuthBackend) cleanup(_ context.Context) {
	b.l.Lock()
	if b.updaterCtxCancel != nil {
		b.updaterCtxCancel()
	}
	b.l.Unlock()
}
