package secrets

import (
	"github.com/zalando/go-keyring"
	"os/user"
)

// Keychain defines a keychain.
type Keychain struct {
	service string
	account string
}

// NewKeychain creates a new keychain.
func NewKeychain(service string, user user.User) *Keychain {
	return &Keychain{
		service: service,
		account: user.Username,
	}
}

// Put saves a secret.
func (k *Keychain) Put(secret string) error {
	return keyring.Set(k.service, k.account, secret)
}

// Get retrieves a secret.
func (k *Keychain) Get() (string, error) {
	return keyring.Get(k.service, k.account)
}

// Delete deletes a secret.
func (k *Keychain) Delete() error {
	return keyring.Delete(k.service, k.account)
}
