package cognito_config

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type CognitoConfig struct {
	ClientID       string `yaml:"client_id"`
	IdentityPoolID string `yaml:"identity_pool_id"`
	UserPoolID     string `yaml:"user_pool_id"`
}

// Load aws credentials from a file.
func LoadFromFile(file string) (CognitoConfig, error) {

	var config CognitoConfig

	if _, err := os.Stat(file); os.IsNotExist(err) {
		return CognitoConfig{}, errors.Wrap(err, "Config file does not exist")
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return CognitoConfig{}, errors.Wrap(err, "Failed to read config file")
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return CognitoConfig{}, errors.Wrap(err, "Failed to unmarshal credentials")
	}

	err = config.Validate()
	if err != nil {
		return CognitoConfig{}, errors.Wrap(err, "Validation failed")
	}

	return config, nil
}

// Validate the aws credentials.
func (c *CognitoConfig) Validate() error {
	if c.IdentityPoolID == "" {
		return errors.New("not found: identity_pool")
	}

	if c.ClientID == "" {
		return errors.New("not found: client_id")
	}

	if c.UserPoolID == "" {
		return errors.New("not found: user_pool_id")
	}

	return nil
}
