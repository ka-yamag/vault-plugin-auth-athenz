package athenzauth

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/athenz"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/config"
)

const (
	backendHelp = `
The "athenz" credential provider allows authentication using Athenz.
`
	defaultConfigPath = "/etc/vault/plugin/athenz_plugin.yaml"
)

var confPath = ""

// SetConfigPath sets the config file path for athenz updator daemon
func SetConfigPath(path string) {
	confPath = path
}

type athenzAuthBackend struct {
	*framework.Backend

	l *sync.RWMutex

	updaterCtx       context.Context
	updaterCtxCancel context.CancelFunc
}

// Factory is used by framework
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	if p, ok := c.Config["--config-file"]; ok {
		confPath = p
	}
	if confPath == "" {
		confPath = defaultConfigPath
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

// Backend is ...
func backend() (*athenzAuthBackend, error) {
	var b athenzAuthBackend
	b.updaterCtx, b.updaterCtxCancel = context.WithCancel(context.Background())

	if confPath == "" {
		confPath = defaultConfigPath
	}

	conf, err := config.NewConfig(confPath)
	if err != nil {
		return nil, err
	}

	if err := athenz.NewValidator(b.updaterCtx, conf.Athenz); err != nil {
		return nil, err
	}

	// Start validator
	athenz.GetValidator().Run(b.updaterCtx)

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
