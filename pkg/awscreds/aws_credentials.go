package awscreds

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"time"
)

// Credentials type
type Credentials struct {
	AccessKey       string    `yaml:"access_key"`
	SecretAccessKey string    `yaml:"secret_access_key"`
	SessionToken    string    `yaml:"session_token"`
	Expiry          time.Time `yaml:"expiry"`
}

// CredentialsCache handles getting and putting credentials from a cache
type CredentialsCache struct {
	filename string
}

// NewCredentialsCache creates a new instance
func NewCredentialsCache(filename string) *CredentialsCache {
	return &CredentialsCache{
		filename: filename,
	}
}

// Get loads awscreds credentials from cache.
func (c *CredentialsCache) Get() (Credentials, error) {

	var credentials Credentials

	if _, err := os.Stat(c.filename); os.IsNotExist(err) {
		return Credentials{}, errors.Wrap(err, "Credentials file does not exist")
	}

	data, err := ioutil.ReadFile(c.filename)
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Failed to read credentials file")
	}

	err = yaml.Unmarshal(data, &credentials)
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Failed to unmarshal credentials")
	}

	err = credentials.Validate()
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Validation failed")
	}

	return credentials, nil
}

// Put saves awscreds credentials to cache.
func (c *CredentialsCache) Put(credentials Credentials) error {
	// Create parent directory if it doesn't exist.
	if _, err := os.Stat(c.filename); os.IsNotExist(err) {
		dir := path.Dir(c.filename)
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return errors.Wrap(err, "Failed to create directory")
		}
	}

	credBytes, err := yaml.Marshal(credentials)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal credentials")
	}
	err = ioutil.WriteFile(c.filename, credBytes, 0644)
	if err != nil {
		return errors.Wrap(err, "Failed to write credentials to file")
	}
	return nil
}

// Delete the credentials from cache.
func (c *CredentialsCache) Delete() error {
	err := os.Remove(c.filename)
	if err != nil {
		return errors.Wrap(err, "Failed to delete credentials file")
	}
	return nil
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
