package athenzauth

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/katyamag/vault-plugin-auth-athenz/pkg/athenz"
	"github.com/stretchr/testify/assert"
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
)

func createTestAthenzConfig(data []byte) (string, string) {
	// Create directory to place configuration files
	tmpDir, _ := ioutil.TempDir("", "test")
	configFilePath := filepath.Join(tmpDir, "data.yaml")

	// Prepare for a test configuration file
	ioutil.WriteFile(configFilePath, []byte(basicConfig), 0644)

	return tmpDir, configFilePath
}

func testConfigWrite(t *testing.T, d map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "athenz",
		Data:      d,
	}
}

func TestSetConfigPath(t *testing.T) {
	path := "/tmp/config.hcl"
	SetConfigPath(path)
	assert.Equal(t, path, confPath)

	path = "/etc/test/path"
	SetConfigPath(path)
	assert.Equal(t, path, confPath)
}

func TestBackend_Basic(t *testing.T) {
	tmpDir, configFilePath := createTestAthenzConfig([]byte(basicConfig))
	defer func() {
		err := os.RemoveAll(tmpDir)
		if err != nil {
			t.Error(err)
		}
	}()

	storage := &logical.InmemStorage{}
	config := logical.TestBackendConfig()
	config.StorageView = storage
	config.Config = map[string]string{
		"--config-file": configFilePath,
	}

	athenz.SetMockAthenz(&athenz.MockAthenz{})

	ctx := context.Background()
	b, err := Factory(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatalf("failed to create backend")
	}

	logicaltest.Test(t, logicaltest.TestCase{
		CredentialBackend: b,
		Steps:             []logicaltest.TestStep{},
	})
}

// func TestBackend_FailedConfigValidation(t *testing.T) [
// }
