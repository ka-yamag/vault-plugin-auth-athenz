package athenzauth

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	hlog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/athenz"
)

const (
	basicConfig = `---
athenz:
  url: https://test.athenz.com/zts/v1
  pubkeyRefreshDuration: 2m
  policyRefreshDuration: 6h
  domain: sample.domain
  policy:
    resource: vault
    action: access
`

	invalidConfig = `---
athenz:
  invalid-config
  url: https://test.athenz.com/zts/v1
  pubkeyRefreshDuration: 2m
  policyRefreshDuration: 6h
  domain: sample.domain
  policy:
    resource: vault
    action: access
`

	invalidAthenzParamConfig = `---
athenz:
  url: http://[fe80::1%en0]
  doain: 00domain
`
)

func createTestAthenzConfig(data []byte) (string, string) {
	// Create directory to place configuration files
	tmpDir, _ := ioutil.TempDir("", "test")
	configFilePath := filepath.Join(tmpDir, "data.yaml")

	// Prepare for a test configuration file
	ioutil.WriteFile(configFilePath, data, 0644)

	return tmpDir, configFilePath
}

func TestFactory_CreateFailure(t *testing.T) {

	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24

	tests := []struct {
		name         string
		athenzConfig []byte
		withoutPath  bool
		athenz.MockAthenz
		expectedErr string
	}{
		{
			name:         "without config path",
			athenzConfig: []byte(basicConfig),
			withoutPath:  true,
			MockAthenz:   athenz.MockAthenz{},
			expectedErr:  "athenz config path not set",
		},
		{
			name:         "invalid config",
			athenzConfig: []byte(invalidConfig),
			MockAthenz:   athenz.MockAthenz{},
			expectedErr:  "yaml: line 4: mapping values are not allowed in this context",
		},
		{
			name:         "failed to load athenz config",
			athenzConfig: []byte(invalidAthenzParamConfig),
			MockAthenz:   athenz.MockAthenz{},
			expectedErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, path := createTestAthenzConfig(tt.athenzConfig)
			defer func() {
				err := os.RemoveAll(tmpDir)
				if err != nil {
					t.Error(err)
				}
			}()
			athenz.SetMockAthenz(&athenz.MockAthenz{})

			backendConfig := &logical.BackendConfig{
				Config: map[string]string{
					"--config-file": func() string {
						if tt.withoutPath {
							return ""
						}

						return path
					}(),
				},
				Logger: logging.NewVaultLogger(hlog.Trace),
				System: &logical.StaticSystemView{
					DefaultLeaseTTLVal: defaultLeaseTTLVal,
					MaxLeaseTTLVal:     maxLeaseTTLVal,
				},
				StorageView: &logical.InmemStorage{},
			}

			_, actual := Factory(context.Background(), backendConfig)
			if actual != nil && actual.Error() != tt.expectedErr {
				t.Errorf("Factory() actual = %v, expected = %v", actual, tt.expectedErr)
				return
			}
		})
	}
}

// func TestSetConfigPath(t *testing.T) {
//   path := "/tmp/config.hcl"
//   SetConfigPath(path)
//   assert.Equal(t, path, confPath)

//   path = "/etc/test/path"
//   SetConfigPath(path)
//   assert.Equal(t, path, confPath)
// }
