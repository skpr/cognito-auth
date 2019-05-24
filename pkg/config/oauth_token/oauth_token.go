package oauth_token

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type OAuthToken struct {
	AccessToken  string `yaml:"access_token"`
	RefreshToken string `yaml:"refresh_token"`
	Expiry       string `yaml:"expiry"`
}

// ReadFromFile will return the oauth token from a file.
func ReadFromFile(filename string) (OAuthToken, error) {

	var token OAuthToken

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return OAuthToken{}, errors.Wrap(err, "failed to load token")
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return OAuthToken{}, errors.Wrap(err, "failed to read token")
	}

	err = yaml.Unmarshal(data, &token)
	if err != nil {
		return OAuthToken{}, errors.Wrap(err, "failed to unmarshal token")
	}

	err = token.Validate()
	if err != nil {
		return OAuthToken{}, errors.Wrap(err, "validation failed")
	}

	return token, nil
}

// WriteToFile writes an oauth token to file
func WriteToFile(filename string, token OAuthToken) error {

	data, err := yaml.Marshal(&token)
	if err != nil {
		return errors.Wrap(err, "failed to marshal token")
	}

	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write token")
	}

	return nil
}

// Validate the OAuth token file.
func (c OAuthToken) Validate() error {
	if c.AccessToken == "" {
		return errors.New("not found: access_token")
	}

	if c.RefreshToken == "" {
		return errors.New("not found: refresh_token")
	}

	if c.Expiry == "" {
		return errors.New("not found: expiry")
	}

	return nil
}
