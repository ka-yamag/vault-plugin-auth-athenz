package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	// Create directory to place configuration files
	tmpDir, _ := ioutil.TempDir("", "test")
	defer func() {
		err := os.RemoveAll(tmpDir)
		if err != nil {
			t.Error(err)
		}
	}()
	configPath := filepath.Join(tmpDir, "data.yaml")

	tests := []struct {
		data     string
		path     string
		expected *Config
		err      error
	}{
		{
			data: `---
athenz:
  url: localhost:4443/zts/v1
  refreshDuration: 6h
  domain:
    - sample.domain
    - sample
  policy:
    resource: vault
    action: access
`,
			path: configPath,
			expected: &Config{
				Athenz: Athenz{
					URL:             "localhost:4443/zts/v1",
					RefreshDuration: "6h",
					Domain: []string{
						"sample.domain",
						"sample",
					},
					Policy: Policy{
						Resource: "vault",
						Action:   "access",
					},
				},
			},
			err: nil,
		},
		{
			path: "/no/exist/path/data.yaml",
			err:  fmt.Errorf("open /no/exist/path/data.yaml: no such file or directory"),
		},
		{
			data: "not yaml",
			path: configPath,
			err:  fmt.Errorf("yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `not yaml` into config.Config"),
		},
	}

	for _, test := range tests {
		// Prepare for a test configuration file
		ioutil.WriteFile(configPath, []byte(test.data), 0644)

		conf, actualErr := NewConfig(test.path)
		if actualErr != nil {
			assert.Equal(t, test.err.Error(), actualErr.Error())
		}
		assert.Exactly(t, test.expected, conf)
	}
}
