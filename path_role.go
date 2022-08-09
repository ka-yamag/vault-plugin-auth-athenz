package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type athenzRoleEntry struct {
	tokenutil.TokenParams

	Role string

	// Deprecated: These are superceded by TokenUtil
	// TTL      time.Duration
	// MaxTTL   time.Duration
	Policies []string
}

func (a *athenzRoleEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{}

	a.PopulateTokenData(responseData)
	// if entry.TTL.Seconds() > 0 {
	//   responseData["ttl"] = int64(entry.TTL.Seconds())
	// }
	// if entry.MaxTTL.Seconds() > 0 {
	//   responseData["max_ttl"] = int64(entry.MaxTTL.Seconds())
	// }
	if len(a.Policies) > 0 {
		responseData["policies"] = responseData["token_policies"]
	}

	return responseData
}

func (b *backend) pathListRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/?",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRoleList,
			},
		},
	}
}

func (b *backend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role in vault.",
			},

			"role": {
				Type:        framework.TypeString,
				Description: "Name of the athenz role.",
			},

			"policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: tokenutil.DeprecationText("token_policies"),
				Deprecated:  true,
			},

			// "ttl": {
			//   Type:        framework.TypeDurationSecond,
			//   Description: tokenutil.DeprecationText("token_ttl"),
			//   Deprecated:  true,
			// },

			// "max_ttl": {
			//   Type:        framework.TypeDurationSecond,
			//   Description: tokenutil.DeprecationText("token_max_ttl"),
			//   Deprecated:  true,
			// },
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathRoleCreateUpdate,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleCreateUpdate,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
			},
		},

		// TODO
		// HelpSynopsis:    pathRoleSyn,
		// HelpDescription: pathRoleDesc,
	}
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(data.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse("name must be set"), nil
	}

	roleName := strings.ToLower(data.Get("role").(string))
	if roleName == "" {
		return logical.ErrorResponse("missing athenz role name"), nil
	}

	roleEntry, err := b.athenzRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if roleEntry == nil {
		roleEntry = &athenzRoleEntry{
			Role: roleName,
		}
	}

	if err := tokenutil.UpgradeValue(data, "policies", "token_policies", &roleEntry.Policies, &roleEntry.TokenPolicies); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON("role/"+name, roleEntry)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) athenzRole(ctx context.Context, s logical.Storage, roleName string) (*athenzRoleEntry, error) {
	b.roleMutex.Lock()
	defer b.roleMutex.Unlock()

	// Fetch from storage
	entry, err := s.Get(ctx, "role/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	result := new(athenzRoleEntry)
	if err := entry.DecodeJSON(result); err != nil {
		return nil, err
	}

	return result, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := b.athenzRole(ctx, req.Storage, strings.ToLower(data.Get("role").(string)))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.ToResponseData(),
	}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.roleMutex.Lock()
	defer b.roleMutex.Unlock()

	if err := req.Storage.Delete(ctx, "role/"+strings.ToLower(roleName)); err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}

	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}
