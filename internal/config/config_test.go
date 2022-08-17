package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNewConfig(t *testing.T) {
	// Create directory to place configuration files
	tmpDir, _ := os.MkdirTemp("", "test")
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
  ztsURL: localhost:4443/zts/v1
  pubkeyRefreshDuration: 2m
  policyRefreshDuration: 6h
  providerDomain: sample.domain
`,
			path: configPath,
			expected: &Config{
				Athenz: Athenz{
					ZtsURL:                "localhost:4443/zts/v1",
					PolicyRefreshDuration: "6h",
					ProviderDomain:        "sample.domain",
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
		os.WriteFile(configPath, []byte(test.data), 0644)

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
