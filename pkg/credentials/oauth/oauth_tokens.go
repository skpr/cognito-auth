package oauth

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"time"
)

// Tokens type
type Tokens struct {
	AccessToken  string    `yaml:"access_token"`
	RefreshToken string    `yaml:"refresh_token"`
	IDToken      string    `yaml:"id_token"`
	Expiry       time.Time `yaml:"expiry"`
}

// TokensCache handles caching oauth2 tokens.
type TokensCache struct {
	filename string
}

// NewTokensCache creates a new instance.
func NewTokensCache(filename string) TokensCache {
	return TokensCache{
		filename: filename,
	}
}

// Get will return the oauth token from cache.
func (c *TokensCache) Get() (Tokens, error) {

	var token Tokens

	if _, err := os.Stat(c.filename); os.IsNotExist(err) {
		return Tokens{}, errors.Wrap(err, "failed to load token")
	}

	data, err := ioutil.ReadFile(c.filename)
	if err != nil {
		return Tokens{}, errors.Wrap(err, "failed to read token")
	}

	err = yaml.Unmarshal(data, &token)
	if err != nil {
		return Tokens{}, errors.Wrap(err, "failed to unmarshal token")
	}

	err = token.Validate()
	if err != nil {
		return Tokens{}, errors.Wrap(err, "validation failed")
	}

	return token, nil
}

// Put writes an oauth token to cache.
func (c *TokensCache) Put (token Tokens) error {

	// Create parent directory if it doesn't exist.
	if _, err := os.Stat(c.filename); os.IsNotExist(err) {
		dir := path.Dir(c.filename)
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return errors.Wrap(err, "Failed to create directory")
		}
	}

	data, err := yaml.Marshal(&token)
	if err != nil {
		return errors.Wrap(err, "failed to marshal tokens")
	}

	err = ioutil.WriteFile(c.filename, data, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write tokens")
	}

	return nil
}

// Delete the tokens file.
func (c *TokensCache) Delete() error {
	err := os.Remove(c.filename)
	if err != nil {
		return errors.Wrap(err, "Failed to delete tokens file")
	}
	return nil
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
