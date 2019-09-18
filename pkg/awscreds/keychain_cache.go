package awscreds

import (
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/secrets"
	"gopkg.in/yaml.v2"
)

// KeychainCache handles caching aws creds in the keychain.
type KeychainCache struct {
	keychain secrets.Keychain
}

// NewKeychainCache creates a new keychain cache.
func NewKeychainCache(keychain *secrets.Keychain) *KeychainCache {
	return &KeychainCache{
		keychain: *keychain,
	}
}

// Get gets creds from the cache.
func (k KeychainCache) Get() (Credentials, error) {
	var credentials Credentials

	data, err := k.keychain.Get()
	if err != nil {
		return Credentials{}, errors.Wrap(err, "failed to get credentials")
	}

	err = yaml.Unmarshal([]byte(data), &credentials)
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Failed to unmarshal credentials")
	}

	err = credentials.Validate()
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Validation failed")
	}

	return credentials, nil
}

// Put puts creds in the cache.
func (k KeychainCache) Put(credentials Credentials) error {
	data, err := yaml.Marshal(credentials)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal credentials")
	}

	if err := k.keychain.Put(string(data)); err != nil {
		return errors.Wrap(err, "failed to put credentials")
	}

	return nil
}

// Delete deletes creds from the cache.
func (k KeychainCache) Delete(credentials Credentials) error {
	if err := k.keychain.Delete(); err != nil {
		return errors.Wrap(err, "failed to delete credentials")
	}
	return nil
}
