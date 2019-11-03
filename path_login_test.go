package athenzauth

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/athenz"
	"github.com/yahoo/athenz/clients/go/zts"
)

func TestClientPath_Login(t *testing.T) {
	b, storage, removeFunc := getBackend(t)
	defer removeFunc()

	athenz.SetMockAthenz(&athenz.MockAthenz{})

	// Create user "testuser"
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Path:      "clients/testuser",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"role":    "test_access1",
			"ttl":     "0",
			"max_ttl": "0",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}

	// Login testuser
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Path:      "login",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"name":  "testuser",
			"role":  "test_access1",
			"token": "test_athenz_token",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}
}

func TestClientPath_LoginFail(t *testing.T) {
	b, storage, removeFunc := getBackend(t)
	defer removeFunc()

	type args struct {
		name  string
		role  string
		token string
	}

	tests := []struct {
		name string
		args
		initFunc    func()
		expectedErr string
	}{
		{
			name: "missing name",
			args: args{
				name: "",
			},
			initFunc: func() {
				athenz.SetMockAthenz(&athenz.MockAthenz{})
			},
			expectedErr: "missing name",
		},
		{
			name: "missing athenz token",
			args: args{
				name:  "testuser",
				token: "",
			},
			initFunc: func() {
				athenz.SetMockAthenz(&athenz.MockAthenz{})
			},
			expectedErr: "missing athenz token",
		},
		{
			name: "failed to verify athenz token",
			args: args{
				name:  "testuser",
				role:  "testrole",
				token: "invalid_token",
			},
			initFunc: func() {
				// Create user "testuser"
				resp, err := b.HandleRequest(context.Background(), &logical.Request{
					Path:      "clients/testuser",
					Operation: logical.UpdateOperation,
					Storage:   storage,
					Data: map[string]interface{}{
						"role":    "testrole",
						"ttl":     "0",
						"max_ttl": "0",
					},
				})
				if err != nil || (resp != nil && resp.IsError()) {
					t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
				}

				athenz.SetMockAthenz(&athenz.MockAthenz{
					RoleToken:      &zts.RoleToken{},
					VerifyTokenErr: errors.New("invalid athenz token"),
				})
			},
			expectedErr: "unauthorized athenz principal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.initFunc()

			// Login testuser
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Path:      "login",
				Operation: logical.UpdateOperation,
				Storage:   storage,
				Data: map[string]interface{}{
					"name":  tt.args.name,
					"role":  tt.args.role,
					"token": tt.args.token,
				},
			})
			if err != nil || resp.Data["error"] != tt.expectedErr {
				t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
				return
			}
		})
	}
}
