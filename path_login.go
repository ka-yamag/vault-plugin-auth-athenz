package main

// TODO: copyright

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role in vault.",
			},

			"role": {
				Type:        framework.TypeString,
				Description: "Name of the athenz role.",
			},

			"role_token": {
				Type:        framework.TypeString,
				Description: "Athenz Role Token",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLoginUpdate,
			},
		},
	}
}

func (b *backend) hasResourceAccessOnAthenz(ctx context.Context, roleToken, action, resource string) error {
	_, err := b.athenzAuthorizerd.AuthorizeRoleToken(ctx, roleToken, action, resource)
	if err != nil {
		return fmt.Errorf("role token not authorized: %v", err)
	}
	return nil
}

func (b *backend) pathLoginRoleToken(ctx context.Context, req *logical.Request, data *framework.FieldData, name, roleName, roleToken string) (*logical.Response, error) {
	// TODO: from args
	if err := b.hasResourceAccessOnAthenz(ctx, roleToken, "login", "vault_login"); err != nil {
		return nil, err
	}

	entry, err := b.athenzRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"role": entry.Role,
			},
			Policies: entry.Policies,
			// LeaseOptions: logical.LeaseOptions{
			//   TTL: entry.TTL,
			// },
		},
	}, nil
}

func (b *backend) pathLoginUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(data.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("name must be set"), nil
	}

	roleName := strings.ToLower(data.Get("role").(string))
	if roleName == "" {
		return nil, fmt.Errorf("missing athenz role name")
	}

	roleToken := data.Get("role_token").(string)
	if roleToken != "" {
		return b.pathLoginRoleToken(ctx, req, data, name, roleName, roleToken)
	}

	// debug
	f, err := os.OpenFile("/tmp/test.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	log.SetOutput(f)
	log.Println(roleName)

	// log.Println(req.Connection)
	// log.Println(req.Connection.ConnState)

	// if req.Connection == nil || req.Connection.ConnState == nil {
	//   return logical.ErrorResponse("tls connection required"), nil
	// }
	// connState := req.Connection.ConnState

	// if connState.PeerCertificates == nil || len(connState.PeerCertificates) == 0 {
	//   return logical.ErrorResponse("client certificate must be supplied"), nil
	// }
	// clientCert := connState.PeerCertificates[0]

	// log.Println(clientCert)

	return logical.ErrorResponse("not implemented"), nil
}
