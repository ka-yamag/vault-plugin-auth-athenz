package plugin

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	authorizerd "github.com/yahoojapan/athenz-authorizer/v5"
)

const (
	backendHelp = `
The "athenz" credential provider allows authentication using Athenz.
`
	// defaultConfigPath = "/etc/vault/plugin/athenz_plugin.yaml"
	defaultAthenzZtsEndpoint              = "tmp.athrenz.com/zts/v1"
	defaultAthenzDomain                   = "tmp.domain"
	defaultAuthorizerdPubkeyRefreshPeriod = "24h"
	defaultAuthorizerdPolicyRefreshPeriod = "10h"
)

type backend struct {
	*framework.Backend

	athenzAuthorizerd authorizerd.Authorizerd
	httpClient        *http.Client

	roleMutex sync.Mutex

	updaterCtx       context.Context
	updaterCtxCancel context.CancelFunc
}

// Factory is used by framework
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	var athenzConfPath string
	if path, ok := conf.Config["--athenz-config-file"]; ok {
		athenzConfPath = path
	}

	b, err := Backend(athenzConfPath)
	if err != nil {
		return nil, err
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(athenzConfPath string) (*backend, error) {
	b := &backend{}
	b.updaterCtx, b.updaterCtxCancel = context.WithCancel(context.Background())

	// TODO: from config
	daemon, err := authorizerd.New(
		authorizerd.WithAthenzURL(defaultAthenzZtsEndpoint),
		authorizerd.WithAthenzDomains(defaultAthenzDomain),
		authorizerd.WithPubkeyRefreshPeriod("1h"),
		authorizerd.WithPolicyRefreshPeriod("5m"),
	)
	if err != nil {
		return nil, fmt.Errorf("athenz authorizer daemon new error: %v", err)
	}

	if err := daemon.Init(b.updaterCtx); err != nil {
		return nil, fmt.Errorf("athenz authorizer daemon init error: %v", err)
	}

	errs := daemon.Start(b.updaterCtx)
	go func() {
		for err := range errs {
			log.Printf("athenz authorizer daemon start error: %v", err)
		}
	}()
	b.athenzAuthorizerd = daemon

	b.Backend = &framework.Backend{
		Help: backendHelp,
		// AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathRole(),
				b.pathListRole(),
				b.pathLogin(),
			},
		),
		BackendType: logical.TypeCredential,
		Clean:       b.cleanup,
	}

	b.roleMutex = sync.Mutex{}

	return b, nil
}

func (b *backend) cleanup(_ context.Context) {
	b.roleMutex.Lock()
	if b.updaterCtxCancel != nil {
		b.updaterCtxCancel()
	}
	b.roleMutex.Unlock()
}
