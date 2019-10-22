package athenzauth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/logger"
)

var (
	log       = logger.GetLogger()
	roleRegxp = regexp.MustCompile(`^([a-zA-Z0-9_][a-zA-Z0-9_-]*)(\.[a-zA-Z0-9_][a-zA-Z0-9_-]*)*$`)
)

const pathPrefix = "clients/"

// AthenzEntry is used to report that the user requests to read athenz/ path
type AthenzEntry struct {
	tokenutil.TokenParams

	Name     string
	Role     string
	Policies []string
	TTL      time.Duration
	MaxTTL   time.Duration
}

func pathConfigClient(b *athenzAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: pathPrefix + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "service name",
			},

			"role": {
				Type:        framework.TypeString,
				Description: "Athenz Role name",
			},

			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_policies"),
				Deprecated:  true,
			},

			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_ttl"),
				Deprecated:  true,
			},

			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: tokenutil.DeprecationText("token_max_ttl"),
				Deprecated:  true,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathClientDelete,
			logical.ReadOperation:   b.pathClientRead,
			logical.UpdateOperation: b.pathClientWrite,
			logical.CreateOperation: b.pathClientWrite,
		},

		// HelpSynopsis: pathAthenzHelpSyn,
	}
}

func (b *athenzAuthBackend) pathClientWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("name must be set"), nil
	}

	athenzEntry, err := b.athenz(ctx, req.Storage, strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}

	if athenzEntry == nil {
		athenzEntry = &AthenzEntry{}
	}

	// Parse role name
	role := d.Get("role").(string)
	if !roleRegxp.Copy().MatchString(role) {
		return logical.ErrorResponse("invalid role name"), nil
	}

	if err := tokenutil.UpgradeValue(d, "policies", "token_policies", &athenzEntry.Policies, &athenzEntry.TokenPolicies); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// athenzEntry := &AthenzEntry{
	//   Name:     name,
	//   Role:     role,
	//   Policies: policies,
	//   TTL:      ttl,
	//   MaxTTL:   maxTTL,
	// }

	// Store athenz entry
	// entry, err := logical.StorageEntryJSON(pathPrefix+name, athenzEntry)
	// if err != nil {
	//   return nil, err
	// }
	// if err := req.Storage.Put(ctx, entry); err != nil {
	//   return nil, err
	// }

	// if len(resp.Warnings) == 0 {
	//   return nil, nil
	// }

	return &resp, nil
}

func (b *athenzAuthBackend) pathClientRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	athenz, err := b.athenz(ctx, req.Storage, strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}
	if athenz == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":           athenz.Name,
			"athenz role":    athenz.Role,
			"vault policies": athenz.Policies,
			"ttl":            athenz.TTL.Seconds(),
			"max_ttl":        athenz.MaxTTL.Seconds(),
		},
	}, nil
}

func (b *athenzAuthBackend) athenz(ctx context.Context, s logical.Storage, name string) (*AthenzEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	entry, err := s.Get(ctx, pathPrefix+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, errors.New("missing vault entry")
	}

	result := AthenzEntry{}
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *athenzAuthBackend) pathClientDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, pathPrefix+strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}
	return nil, nil
}
