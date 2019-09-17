package oauth

import (
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/secrets"
	"gopkg.in/yaml.v2"
)

// KeychainCache handles caching oauth2 tokens in the keychain.
type KeychainCache struct {
	keychain secrets.Keychain
}

// NewKeychainCache creates a new keychain cache.
func NewKeychainCache(label string, service string, account string) *KeychainCache {
	keychain := secrets.NewKeychain(label, service, account)
	return &KeychainCache{
		keychain: *keychain,
	}
}

// Get gets the tokens from the keychain.
func (k KeychainCache) Get() (Tokens, error) {
	var tokens Tokens

	data, err := k.keychain.Get()
	if err != nil {
		return Tokens{}, errors.Wrap(err, "failed to get tokens")
	}

	err = yaml.Unmarshal([]byte(data), &tokens)
	if err != nil {
		return Tokens{}, errors.Wrap(err, "failed to unmarshal tokens")
	}

	return tokens, nil
}

// Put puts the tokens from the keychain.
func (k KeychainCache) Put(token Tokens) error {
	data, err := yaml.Marshal(&token)
	if err != nil {
		return errors.Wrap(err, "failed to marshal tokens")
	}
	if err := k.keychain.Put(string(data)); err != nil {
		return errors.Wrap(err, "failed to put tokens")
	}
	return nil
}

// Delete deletes the tokens from the keychain.
func (k KeychainCache) Delete(token Tokens) error {
	if err := k.keychain.Delete(); err != nil {
		return errors.Wrap(err, "failed to delete tokens")
	}
	return nil
}
