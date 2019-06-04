package oauth

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
)

// Constants
const (
	filename = "oauth_tokens.yml"
)

// TokensCache handles caching oauth2 tokens.
type TokensCache struct {
	filename string
}

// NewTokensCache creates a new instance.
func NewTokensCache(cacheDir string) *TokensCache {
	filename := cacheDir + filename
	return &TokensCache{
		filename: filename,
	}
}

// Get will return the oauth token from cache.
func (c *TokensCache) Get() (Tokens, error) {

	var tokens Tokens

	if _, err := os.Stat(c.filename); os.IsNotExist(err) {
		return Tokens{}, errors.Wrap(err, "failed to load tokens")
	}

	data, err := ioutil.ReadFile(c.filename)
	if err != nil {
		return Tokens{}, errors.Wrap(err, "failed to read tokens")
	}

	err = yaml.Unmarshal(data, &tokens)
	if err != nil {
		return Tokens{}, errors.Wrap(err, "failed to unmarshal tokens")
	}

	err = tokens.Validate()
	if err != nil {
		return Tokens{}, errors.Wrap(err, "validation failed")
	}

	return tokens, nil
}

// Put writes an oauth token to cache.
func (c *TokensCache) Put(token Tokens) error {

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
