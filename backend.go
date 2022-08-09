package main

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
)

// var confPath = ""

// SetConfigPath sets the config file path for athenz updator daemon
// func SetConfigPath(path string) {
//   confPath = path
// }

type backend struct {
	*framework.Backend

	athenzAuthorizerd authorizerd.Authorizerd
	httpClient        *http.Client

	roleMutex sync.Mutex

	updaterCtx       context.Context
	updaterCtxCancel context.CancelFunc
}

// factory is used by framework
func factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	// if p, ok := c.Config["--config-file"]; ok {
	//   confPath = p
	// }
	// if confPath == "" {
	//   return nil, errors.New("athenz config path not set")
	// }

	b, err := Backend()
	if err != nil {
		return nil, err
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() (*backend, error) {
	b := &backend{}
	b.updaterCtx, b.updaterCtxCancel = context.WithCancel(context.Background())

	// TODO: from config
	daemon, err := authorizerd.New(
		authorizerd.WithAthenzURL("apj.zts.athenz.yahoo.co.jp:4443/zts/v1"),
		authorizerd.WithAthenzDomains("yby.katyamag"),
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
