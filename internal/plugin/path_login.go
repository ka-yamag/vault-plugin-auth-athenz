package plugin

import (
	"context"
	"fmt"
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

			"athenz_role": {
				Type:        framework.TypeString,
				Description: "Name of the athenz role.",
				Required:    true,
			},

			"role_token": {
				Type:        framework.TypeString,
				Description: "Athenz Role Token",
			},

			// "access_token": {
			//   Type:        framework.TypeString,
			//   Description: "Athenz Access Token issued by Corporate IdP",
			// },
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLoginUpdate,
			},
		},
	}
}

func (b *backend) pathLoginUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(data.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("name must be set"), nil
	}

	entry, err := b.athenzRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if roleToken, ok := data.GetOk("role_token"); ok {
		principal, err := b.athenzAuthorizerd.AuthorizeRoleToken(ctx, roleToken.(string), entry.AthenzPolicyAction, entry.AthenzPolicyResource)
		if err != nil {
			return nil, fmt.Errorf("not authorized: %v", err)
		}

		validation := func() bool {
			for _, role := range principal.Roles() {
				if role == entry.AthenzRole {
					return true
				}
			}
			return false
		}

		if !validation() {
			return logical.ErrorResponse("role doesn't match"), nil
		}
	}

	// if accessToken, ok := data.GetOk("access_token"); ok {
	//   clientCert := req.Connection.ConnState.PeerCertificates
	//   if len(clientCert) == 0 {
	//     return logical.ErrorResponse("no client certificate found"), nil
	//   }
	//   _, err := b.athenzAuthorizerd.AuthorizeAccessToken(ctx,
	//     accessToken.(string), entry.AthenzPolicyAction, entry.AthenzPolicyResource, clientCert[0])
	//   if err != nil {
	//     return nil, fmt.Errorf("not authorized: %v", err)
	//   }
	// }

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"athenz_role":            entry.AthenzRole,
				"athenz_policy_action":   entry.AthenzPolicyAction,
				"athenz_policy_resource": entry.AthenzPolicyResource,
			},
			Policies: entry.Policies,
			// LeaseOptions: logical.LeaseOptions{
			//   TTL: entry.TTL,
			// },
		},
	}, nil
}
