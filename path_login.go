package athenzauth

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/athenz"
)

func pathLogin(b *athenzAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"token": &framework.FieldSchema{
				Type: framework.TypeString,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathAuthLogin,
		},
	}
}

func (b *athenzAuthBackend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("name").(string))
	if name == "" {
		return nil, errors.New("missing name")
	}

	roletoken := d.Get("token").(string)
	if roletoken == "" {
		return nil, errors.New("missing athenz token")
	}

	athenzEntry, err := b.athenz(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	_, err = athenz.GetValidator().VerifyToken(ctx, d.Get("token").(string), athenzEntry.Role)
	if err != nil {
		return logical.ErrorResponse("unauthorized athenz principal"), nil
	}

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"name": athenzEntry.Name,
				"role": athenzEntry.Role,
			},
			Policies: athenzEntry.Policies,
			Metadata: map[string]string{
				"name": athenzEntry.Name,
			},
			LeaseOptions: logical.LeaseOptions{
				TTL:       athenzEntry.TTL,
				MaxTTL:    athenzEntry.MaxTTL,
				Renewable: true,
			},
		},
	}, nil
}
