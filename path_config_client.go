package athenzauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathAthenzHelpSyn = `
Manage the athenz principal used for authentication.
	`
)

// AthenzEntry is used to report that the user requests to read athenz/ path
type AthenzEntry struct {
	Name     string
	Role     string
	Policies []string
	TTL      time.Duration
	MaxTTL   time.Duration
}

func pathConfigClient(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "client/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Default:     "",
				Description: "service name",
			},

			"role": {
				Type:        framework.TypeString,
				Default:     "",
				Description: "Athenz Role name",
			},

			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Default:     "",
				Description: `Comma-separated list of policies.`,
			},

			"ttl": {
				Type:        framework.TypeDurationSecond,
				Default:     "",
				Description: `TTL for tokens issued by this backend. Defaults to system/backend default TTL time.`,
			},

			"lease": {
				Type:        framework.TypeInt,
				Default:     "",
				Description: `Deprecated: use "ttl" instead. TTL time in seconds. Defaults to system/backend default TTL.`,
			},

			"max_ttl": {
				Type:    framework.TypeDurationSecond,
				Default: "",
				Description: `Duration in either an integer number of seconds (3600) or an integer time unit (60m)
				after which the issued token can no longer be renewed.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigClientCreateUpdate,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigClientRead,
			},
		},

		// Callbacks: map[logical.Operation]framework.OperationFunc{
		//   // logical.DeleteOperation: b.pathServiceDelete,
		//   // logical.ReadOperation:   b.pathServiceRead,
		//   // logical.UpdateOperation: b.pathServiceWrite,
		// },
		HelpSynopsis: pathAthenzHelpSyn,
	}
}

func (b *backend) pathConfigClientCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("name must be set"), nil
	}

	resp := logical.Response{}

	// Parse the ttl (or lease duration)
	systemDefaultTTL := b.System().DefaultLeaseTTL()
	ttl := time.Duration(d.Get("ttl").(int)) * time.Second
	if ttl == 0 {
		ttl = time.Duration(d.Get("lease").(int)) * time.Second
	}
	if ttl > systemDefaultTTL {
		resp.AddWarning(
			fmt.Sprintf("Given ttl of %d seconds is greater than current mount/system default of %d seconds",
				ttl/time.Second,
				systemDefaultTTL/time.Second,
			),
		)
	}
	if ttl < time.Duration(0) {
		return logical.ErrorResponse("ttl cannot be negative"), nil
	}

	// Parse the max_ttl
	systemMaxTTL := b.System().MaxLeaseTTL()
	maxTTL := time.Duration(d.Get("max_ttl").(int)) * time.Second
	if maxTTL > systemMaxTTL {
		resp.AddWarning(fmt.Sprintf(
			"Given max_ttl of %d seconds is greater than current mount/system default of %d seconds",
			maxTTL/time.Second,
			systemMaxTTL/time.Second),
		)
	}
	if maxTTL < time.Duration(0) {
		return logical.ErrorResponse("max_ttl cannot be negative"), nil
	}
	if maxTTL != 0 && ttl > maxTTL {
		return logical.ErrorResponse("ttl should be shorter than max_ttl"), nil
	}

	// Parse vault policies
	policies := policyutil.ParsePolicies(d.Get("policies"))

	// Parse roletoken
	// parsedRoleToken, err := athenz.GetUpdater().VerifyRoleToken(ctx, d.Get("roletoken").(string))
	// if err != nil {
	//   return logical.ErrorResponse(fmt.Sprintf("could not parse roletoken: %s", err)), nil
	// }

	// TODO: parse role name
	role := d.Get("roletoken").(string)

	athenzEntry := &AthenzEntry{
		Name:     name,
		Role:     role,
		Policies: policies,
		TTL:      ttl,
		MaxTTL:   maxTTL,
	}

	// Store athenz entry
	entry, err := logical.StorageEntryJSON("clients/"+name, athenzEntry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if len(resp.Warnings) == 0 {
		return nil, nil
	}

	return &resp, nil
}

func (b *backend) pathConfigClientRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

func (b *backend) athenz(ctx context.Context, s logical.Storage, name string) (*AthenzEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	entry, err := s.Get(ctx, "clients/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	result := AthenzEntry{}
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
