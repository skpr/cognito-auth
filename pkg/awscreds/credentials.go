package awscreds

import (
	"github.com/pkg/errors"
	"time"
)

// Credentials type
type Credentials struct {
	AccessKey       string    `yaml:"access_key"`
	SecretAccessKey string    `yaml:"secret_access_key"`
	SessionToken    string    `yaml:"session_token"`
	Expiry          time.Time `yaml:"expiry"`
}

// Validate the awscreds credentials.
func (c *Credentials) Validate() error {
	if c.AccessKey == "" {
		return errors.New("not found: access_key")
	}

	if c.SecretAccessKey == "" {
		return errors.New("not found: secret_access_key")
	}

	if c.SessionToken == "" {
		return errors.New("not found: session_token")
	}

	return nil
}

// HasExpired checks if the credentials has expired
func (c *Credentials) HasExpired() bool {
	return c.Expiry.Before(time.Now())
}
