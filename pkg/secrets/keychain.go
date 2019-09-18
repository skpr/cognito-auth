package secrets

import (
	"github.com/zalando/go-keyring"
)

// Keychain defines a keychain.
type Keychain struct {
	label   string
	service string
	account string
}

// NewKeychain creates a new keychain.
func NewKeychain(label string, service string, account string) *Keychain {
	return &Keychain{
		label:   label,
		service: service,
		account: account,
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
