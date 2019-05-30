package aws_credentials

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"time"
)

type AwsCredentials struct {
	AccessKey       string    `yaml:"access_key"`
	SecretAccessKey string    `yaml:"secret_access_key"`
	SessionToken    string    `yaml:"session_token"`
	Expiry          time.Time `yaml:"expiry"`
}

// Load aws credentials from a file.
func LoadFromFile(file string) (AwsCredentials, error) {

	var credentials AwsCredentials

	if _, err := os.Stat(file); os.IsNotExist(err) {
		return AwsCredentials{}, errors.Wrap(err, "Credentials file does not exist")
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return AwsCredentials{}, errors.Wrap(err, "Failed to read credentials file")
	}

	err = yaml.Unmarshal(data, &credentials)
	if err != nil {
		return AwsCredentials{}, errors.Wrap(err, "Failed to unmarshal credentials")
	}

	err = credentials.Validate()
	if err != nil {
		return AwsCredentials{}, errors.Wrap(err, "Validation failed")
	}

	return credentials, nil
}

// Save aws credentials to a file.
func SaveToFile(file string, credentials AwsCredentials) error {
	// Create parent directory if it doesn't exist.
	if _, err := os.Stat(file); os.IsNotExist(err) {
		dir := path.Dir(file)
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return errors.Wrap(err, "Failed to create directory")
		}
	}

	credBytes, err := yaml.Marshal(credentials)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal credentials")
	}
	err = ioutil.WriteFile(file, credBytes, 0644)
	if err != nil {
		return errors.Wrap(err, "Failed to write credentials to file")
	}
	return nil
}

// Deletes the credentials file.
func Delete(file string) error {
	err := os.Remove(file)
	if err != nil {
		return errors.Wrap(err, "Failed to delete credentials file")
	}
	return nil
}

// Validate the aws credentials.
func (c *AwsCredentials) Validate() error {
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

// Check if the credentials has expired
func (c *AwsCredentials) HasExpired() bool {
	return c.Expiry.Before(time.Now())
}
