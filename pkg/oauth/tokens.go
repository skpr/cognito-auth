package oauth

import (
	"github.com/pkg/errors"
	"time"
)

// Tokens type
type Tokens struct {
	AccessToken  string    `yaml:"access_token"`
	RefreshToken string    `yaml:"refresh_token"`
	IDToken      string    `yaml:"id_token"`
	Expiry       time.Time `yaml:"expiry"`
}

// Validate the OAuth token file.
func (c *Tokens) Validate() error {
	if c.AccessToken == "" {
		return errors.New("not found: access_token")
	}

	if c.RefreshToken == "" {
		return errors.New("not found: refresh_token")
	}

	if c.IDToken == "" {
		return errors.New("not found: id_token")
	}

	return nil
}

// HasExpired checks if the token has expired.
func (c *Tokens) HasExpired() bool {
	return c.Expiry.Before(time.Now())
}
