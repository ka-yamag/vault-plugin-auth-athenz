package config

import (
	"os"

	yaml "gopkg.in/yaml.v2"
)

// Config contains all the structs
type Config struct {
	Athenz Athenz `yaml:"athenz"`
}

// Athenz is the struct of basic information for athenz
type Athenz struct {
	ZtsURL                string `yaml:"ztsURL"`
	ProviderDomain        string `yaml:"providerDomain"`
	PubkeyRefreshDuration string `yaml:"pubkeyRefreshDutation"`
	PolicyRefreshDuration string `yaml:"policyRefreshDuration"`
}

// NewConfig initializes the yaml config file for athenz server
func NewConfig(path string) (*Config, error) {
	yamlBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := new(Config)
	if err := yaml.Unmarshal(yamlBytes, config); err != nil {
		return nil, err
	}

	return config, nil
}
