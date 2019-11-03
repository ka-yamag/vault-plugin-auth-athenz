package athenzauth

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/go-test/deep"
	hlog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/athenz"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage, func()) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	tmpDir, configFilePath := createTestAthenzConfig([]byte(basicConfig))
	removeFunc := func() {
		err := os.RemoveAll(tmpDir)
		if err != nil {
			t.Error(err)
		}
	}

	config := &logical.BackendConfig{
		Config: map[string]string{
			"--config-file": configFilePath,
		},
		Logger: logging.NewVaultLogger(hlog.Trace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}

	athenz.SetMockAthenz(&athenz.MockAthenz{})

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView, removeFunc
}

func TestClientPath_Create(t *testing.T) {
	b, storage, removeFunc := getBackend(t)
	defer removeFunc()

	type test struct {
		name      string
		checkFunc func() error
	}

	tests := []test{
		func() test {
			data := map[string]interface{}{
				"role": "test_access",
			}

			expectedEntry := &AthenzEntry{
				Name:   "user1",
				Role:   "test_access",
				TTL:    0,
				MaxTTL: 0,
			}

			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "clients/user1",
				Storage:   storage,
				Data:      data,
			}

			return test{
				name: "success",
				checkFunc: func() error {
					resp, err := b.HandleRequest(context.Background(), req)
					if err != nil || (resp != nil && resp.IsError()) {
						return fmt.Errorf("err:%s resp:%#v", err, resp)
					}

					actual, err := b.(*athenzAuthBackend).athenz(context.Background(), storage, "user1")
					if err != nil {
						return err
					}

					if !reflect.DeepEqual(expectedEntry, actual) {
						return fmt.Errorf("Unexpected athenz data: expected %#v got %#v", expectedEntry, actual)
					}

					return nil
				},
			}
		}(),
		func() test {
			username := "user2"

			data := map[string]interface{}{
				"role":    "test_access2",
				"ttl":     "10s",
				"max_ttl": "100s",
			}

			expectedEntry := &AthenzEntry{
				Name:   username,
				Role:   "test_access2",
				TTL:    time.Duration(time.Second * 10),
				MaxTTL: time.Duration(time.Second * 100),
				TokenParams: tokenutil.TokenParams{
					TokenTTL:    time.Duration(time.Second * 10),
					TokenMaxTTL: time.Duration(time.Second * 100),
				},
			}

			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      fmt.Sprintf("clients/%s", username),
				Storage:   storage,
				Data:      data,
			}

			return test{
				name: "success with ttls",
				checkFunc: func() error {
					resp, err := b.HandleRequest(context.Background(), req)
					if err != nil || (resp != nil && resp.IsError()) {
						return fmt.Errorf("err:%s resp:%#v", err, resp)
					}

					actual, err := b.(*athenzAuthBackend).athenz(context.Background(), storage, username)
					if err != nil {
						return err
					}

					if !reflect.DeepEqual(expectedEntry, actual) {
						return fmt.Errorf("Unexpected athenz data: expected %#v got %#v", expectedEntry, actual)
					}

					return nil
				},
			}
		}(),
		func() test {
			username := "user3"

			data := map[string]interface{}{
				"role":     "test_access3",
				"policies": "test, team_pol",
			}

			expectedEntry := &AthenzEntry{
				Name:     username,
				Role:     "test_access3",
				Policies: []string{"team_pol", "test"},
				TokenParams: tokenutil.TokenParams{
					TokenPolicies: []string{"team_pol", "test"},
				},
			}

			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      fmt.Sprintf("clients/%s", username),
				Storage:   storage,
				Data:      data,
			}

			return test{
				name: "success with ttls",
				checkFunc: func() error {
					resp, err := b.HandleRequest(context.Background(), req)
					if err != nil || (resp != nil && resp.IsError()) {
						return fmt.Errorf("err:%s resp:%#v", err, resp)
					}

					actual, err := b.(*athenzAuthBackend).athenz(context.Background(), storage, username)
					if err != nil {
						return err
					}

					if !reflect.DeepEqual(expectedEntry, actual) {
						return fmt.Errorf("Unexpected athenz data: expected %#v got %#v", expectedEntry, actual)
					}

					return nil
				},
			}
		}(),
		func() test {
			data := map[string]interface{}{
				"role": "+-invalid_role",
			}

			expectedErr := "invalid role name"

			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "clients/user",
				Storage:   storage,
				Data:      data,
			}

			return test{
				name: "failed to create if the role is invalid",
				checkFunc: func() error {
					resp, err := b.HandleRequest(context.Background(), req)
					actual := resp.Data["error"]
					if err != nil || actual != expectedErr {
						return fmt.Errorf("Unexpected athenz data: expected %#v got %#v", expectedErr, actual)
					}

					return nil
				},
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.checkFunc()
			if err != nil {
				t.Fatal(err)
				return
			}
		})
	}
}

func TestClientPath_Read(t *testing.T) {
	b, storage, removeFunc := getBackend(t)
	defer removeFunc()

	// Create user "testuser"
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Path:      "clients/testuser",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"role":     "test_access1",
			"ttl":      "10s",
			"max_ttl":  "100s",
			"policies": "test, team_pol",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}

	// Read user "testuser"
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Path:      "clients/testuser",
		Operation: logical.ReadOperation,
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}

	if diff := deep.Equal(resp.Data["policies"].([]string), []string{"team_pol", "test"}); diff != nil {
		t.Fatal(diff)
	}
	if resp.Data["token_ttl"].(int64) != 10 || resp.Data["token_max_ttl"].(int64) != 100 {
		t.Fatalf("bad: token_ttl and token_max_ttl are not set correctly")
	}
}

func TestClientPath_Delete(t *testing.T) {
	b, storage, removeFunc := getBackend(t)
	defer removeFunc()

	// Create user "testuser"
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Path:      "clients/testuser",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"role":     "test_access1",
			"ttl":      "10s",
			"max_ttl":  "100s",
			"policies": "test, team_pol",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}

	// Delete user "testuser"
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Path:      "clients/testuser",
		Operation: logical.DeleteOperation,
		Storage:   storage,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v", resp, err)
	}
}

func TestAthenz(t *testing.T) {
	b, storage, removeFunc := getBackend(t)
	defer removeFunc()

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

	_, err = b.(*athenzAuthBackend).athenz(context.Background(), storage, "testuser")
	if err != nil {
		t.Fatalf("bad: athenz: err: %v", err)
	}

	// not exist
	a, err := b.(*athenzAuthBackend).athenz(context.Background(), storage, "non-exsit")
	if err != nil && a != nil {
		t.Fatalf("bad: athenz: err: %v", err)
	}
}
