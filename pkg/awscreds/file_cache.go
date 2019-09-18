package awscreds

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
)

const (
	filename = "aws_credentials.yml"
)

// FileCache handles getting and putting credentials from a cache
type FileCache struct {
	filename string
}

// NewFileCache creates a new instance
func NewFileCache(cacheDir string) *FileCache {
	file := cacheDir + "/" + filename
	return &FileCache{
		filename: file,
	}
}

// Get loads awscreds credentials from cache.
func (c *FileCache) Get() (Credentials, error) {

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
func (c *FileCache) Put(credentials Credentials) error {
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
func (c *FileCache) Delete(credentials Credentials) error {
	err := os.Remove(c.filename)
	if err != nil {
		return errors.Wrap(err, "Failed to delete credentials file")
	}
	return nil
}
