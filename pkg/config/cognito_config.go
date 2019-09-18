package config

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

// Config type
type Config struct {
	ClientID           string `yaml:"client_id"`
	ClientSecret       string `yaml:"client_secret"`
	IdentityPoolID     string `yaml:"identity_pool_id"`
	IdentityProviderID string `yaml:"identity_provider_id"`
	ConsoleDestination string `yaml:"console_destination"`
	ConsoleIssuer      string `yaml:"console_issuer"`
	CredsStore         string `yaml:"creds_store,omitempty"`
	CredsOAuthKey      string `yaml:"creds_oauth_key,omitempty"`
	CredsAwsKey        string `yaml:"creds_aws_key,omitempty"`
}

// Load load awscreds credentials from a file.
func Load(file string) (Config, error) {
	var config Config

	if _, err := os.Stat(file); os.IsNotExist(err) {
		return Config{}, errors.Wrap(err, "Config file does not exist")
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return Config{}, errors.Wrap(err, "Failed to read config file")
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return Config{}, errors.Wrap(err, "Failed to unmarshal credentials")
	}

	err = config.Validate()
	if err != nil {
		return Config{}, errors.Wrap(err, "Validation failed")
	}

	return config, nil
}

// Validate the awscreds credentials.
func (c *Config) Validate() error {
	if c.IdentityPoolID == "" {
		return errors.New("not found: identity_pool")
	}

	if c.ClientID == "" {
		return errors.New("not found: client_id")
	}

	if c.ConsoleDestination == "" {
		return errors.New("not found: console_destination")
	}

	if c.ConsoleIssuer == "" {
		return errors.New("not found: console_issuer")
	}

	return nil
}
