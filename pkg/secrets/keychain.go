package secrets

import (
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/pkg/errors"
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
	credentials.SetCredsLabel(k.label)
	creds := &credentials.Credentials{
		ServerURL: k.service,
		Username:  k.account,
		Secret:    secret,
	}
	nativeStore := GetNativeStore()
	return nativeStore.Add(creds)
}

// Get retrieves a secret.
func (k *Keychain) Get() (string, error) {
	nativeStore := GetNativeStore()

	_, secret, err := nativeStore.Get(k.service)
	if err != nil {
		return "", errors.Wrap(err, "failed to get secret")
	}
	return secret, nil
}

// Delete deletes a secret.
func (k *Keychain) Delete() error {
	nativeStore := GetNativeStore()
	if err := nativeStore.Delete(k.service); err != nil {
		return errors.Wrap(err, "failed to delete secret")
	}
	return nil
}
