package athenzauth

import (
	"context"
	"errors"
	"fmt"
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
		return logical.ErrorResponse(fmt.Sprintf("could not parse roletoken: %s", err)), nil
	}

	// rt, err := athenz.GetUpdater().VerifyRoleToken(b.updaterCtx, roletoken)
	// if err != nil {
	//   return nil, logical.ErrPermissionDenied
	// }

	// // Check issue domain
	// if athenzEntry.AthenzIssueDomain != rt.Domain {
	//   return nil, errors.New("the issue domain contained in roletoken does not match registerd it")
	// }

	// // Check whether role token includes the registered roles
	// count := 0
	// for _, regRole := range athenzEntry.AthenzRoles {
	//   for _, tokenRole := range rt.Roles {
	//     if regRole == tokenRole {
	//       count++
	//     }
	//   }
	// }
	// if count < len(athenzEntry.AthenzRoles) {
	//   return nil, logical.ErrPermissionDenied
	// }

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				// "athenzIssueDomain": athenzEntry.AthenzIssueDomain,
				// "athenzRoles":       strings.Join(athenzEntry.AthenzRoles, ", "),
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
