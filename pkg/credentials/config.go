package credentials

import (
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type Config struct {
	ClientID       string `yaml:"client_id"`
	ClientSecret   string `yaml:"client_secret"`
	IdentityPoolID string `yaml:"identity_pool_id"`
}

// LoadFromFile will return a configuration from a file.
func LoadFromFile(file, name string) (Config, error) {
	var Configs map[string]Config

	if _, err := os.Stat(file); os.IsNotExist(err) {
		return Config{}, errors.Wrap(err, "Failed to load credentials")
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return Config{}, errors.Wrap(err, "Failed to read credentials")
	}

	err = yaml.Unmarshal(data, &Configs)
	if err != nil {
		return Config{}, errors.Wrap(err, "Failed to marshal credentials")
	}

	if _, ok := Configs[name]; !ok {
		return Config{}, fmt.Errorf("Config not found: %s", name)
	}

	config := Configs[name]

	err = config.Validate()
	if err != nil {
		return Config{}, errors.Wrap(err, "Validation failed")
	}

	return config, nil
}

func (c Config) Validate() error {
	if c.ClientID == "" {
		return errors.New("Not found: client_id")
	}

	if c.ClientSecret == "" {
		return errors.New("Not found: client_secret")
	}

	if c.IdentityPoolID == "" {
		return errors.New("Not found: identity_pool_id")
	}

	return nil
}
