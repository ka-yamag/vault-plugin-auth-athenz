package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
  pubkeyRefreshDuration: 2m
  policyRefreshDuration: 6h
  domain: sample.domain
  policy:
    resource: vault
    action: access
`,
			path: configPath,
			expected: &Config{
				Athenz: Athenz{
					URL:                   "localhost:4443/zts/v1",
					PolicyRefreshDuration: "6h",
					Domain:                "sample.domain",
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
			if test.err.Error() != actualErr.Error() {
				t.Errorf("expect doesn't match: actual: %v, expect: %v", test.err, actualErr)
			}
		}
		if !reflect.DeepEqual(test.expected, conf) {
			t.Errorf("expect doesn't match: actual: %v, expect: %v", test.expected, conf)
		}
	}
}
