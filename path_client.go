package athenzauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/katyamag/vault-plugin-auth-athenz/pkg/logger"
)

var log = logger.GetLogger()

const pathPrefix = "clients/"

// AthenzEntry is used to report that the user requests to read athenz/ path
type AthenzEntry struct {
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
				Description: `Comma-separated list of policies.`,
			},

			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: `TTL for tokens issued by this backend. Defaults to system/backend default TTL time.`,
			},

			"lease": {
				Type:        framework.TypeInt,
				Description: `Deprecated: use "ttl" instead. TTL time in seconds. Defaults to system/backend default TTL.`,
			},

			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: `Duration in either an integer number of seconds (3600) or an integer time unit (60m) after which the issued token can no longer be renewed.`,
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
	log.Debug("pathConfigClient ----")

	name := strings.ToLower(d.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("name must be set"), nil
	}

	log.Debug(name)

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

	log.Debug("ttl ---------------")

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

	log.Debug("maxttl ---------------")

	// Parse vault policies
	policies := policyutil.ParsePolicies(d.Get("policies"))

	log.Debug("policy ---------------")

	// TODO: parse role name
	role := d.Get("role").(string)
	log.Debug("role ---------------")
	log.Debug(role)

	athenzEntry := &AthenzEntry{
		Name:     name,
		Role:     role,
		Policies: policies,
		TTL:      ttl,
		MaxTTL:   maxTTL,
	}

	// Store athenz entry
	entry, err := logical.StorageEntryJSON(pathPrefix+name, athenzEntry)
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
		return nil, nil
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
