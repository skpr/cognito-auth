package oauth_tokens

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"time"
)

type OAuthTokens struct {
	AccessToken  string    `yaml:"access_token"`
	RefreshToken string    `yaml:"refresh_token"`
	Expiry       time.Time `yaml:"expiry"`
}

// ReadFromFile will return the oauth token from a file.
func LoadFromFile(filename string) (OAuthTokens, error) {

	var token OAuthTokens

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return OAuthTokens{}, errors.Wrap(err, "failed to load token")
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return OAuthTokens{}, errors.Wrap(err, "failed to read token")
	}

	err = yaml.Unmarshal(data, &token)
	if err != nil {
		return OAuthTokens{}, errors.Wrap(err, "failed to unmarshal token")
	}

	err = token.Validate()
	if err != nil {
		return OAuthTokens{}, errors.Wrap(err, "validation failed")
	}

	return token, nil
}

// WriteToFile writes an oauth token to file
func SaveToFile(filename string, token OAuthTokens) error {

	// Create parent directory if it doesn't exist.
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		dir := path.Dir(filename)
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return errors.Wrap(err, "Failed to create directory")
		}
	}

	data, err := yaml.Marshal(&token)
	if err != nil {
		return errors.Wrap(err, "failed to marshal tokens")
	}

	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write tokens")
	}

	return nil
}

// Validate the OAuth token file.
func (c *OAuthTokens) Validate() error {
	if c.AccessToken == "" {
		return errors.New("not found: access_token")
	}

	if c.RefreshToken == "" {
		return errors.New("not found: refresh_token")
	}

	return nil
}

// Check if the token has expired.
func (c *OAuthTokens) HasExpired() bool {
	return c.Expiry.Before(time.Now())
}
