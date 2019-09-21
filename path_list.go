package athenzauth

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathListClients(b *athenzAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "clients/?",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathServiceList,
		},
	}
}

func (b *athenzAuthBackend) pathServiceList(
	ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	clients, err := req.Storage.List(ctx, pathPrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(clients), nil
}
