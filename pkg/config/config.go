package config

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

// Config contains all the structs
type Config struct {
	Athenz Athenz `yaml:"athenz"`
}

// Athenz is the struct of basic infomation for athenz
type Athenz struct {
	URL             string   `yaml:"url"`
	RefreshDuration string   `yaml:"refreshDuration"`
	Domain          []string `yaml:"domain"`
	Policy          Policy   `yaml:"policy"`
}

// Policy is the struct for policy to validate access
type Policy struct {
	Resource string `yaml:"resource"`
	Action   string `yaml:"action"`
}

// NewConfig initializes the kmsconsole config with YAML
func NewConfig(path string) (*Config, error) {
	yamlBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	c := new(Config)
	err = yaml.Unmarshal(yamlBytes, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}
