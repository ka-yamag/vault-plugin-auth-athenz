package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	athenz "github.com/ka-yamag/vault-plugin-auth-athenz/internal/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: athenz.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		// TODO: use hclog
		log.Println(err)
		os.Exit(1)
	}
}
