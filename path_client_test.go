package athenzauth

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	hlog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/athenz"
)

func getBackend(t *testing.T, path string) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	config := &logical.BackendConfig{
		Config: map[string]string{
			"--config-file": path,
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

	return b, config.StorageView
}

func TestClientPath_Create(t *testing.T) {
	tmpDir, configFilePath := createTestAthenzConfig([]byte(basicConfig))
	defer func() {
		err := os.RemoveAll(tmpDir)
		if err != nil {
			t.Error(err)
		}
	}()
	b, storage := getBackend(t, configFilePath)

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.checkFunc()
			if err != nil {
				t.Error(err)
				return
			}
		})
	}
}
