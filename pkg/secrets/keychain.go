package secrets

import (
	"github.com/docker/docker-credential-helpers/client"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/pkg/errors"
	"runtime"
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
	return client.Store(k.getNativeStore(), creds)
}

// Get retrieves a secret.
func (k *Keychain) Get() (string, error) {
	creds, err := client.Get(k.getNativeStore(), k.service)
	if err != nil {
		return "", errors.Wrap(err, "failed to get secret")
	}
	return creds.Secret, nil
}

// Delete deletes a secret.
func (k *Keychain) Delete() error {
	if err := client.Erase(k.getNativeStore(), k.service); err != nil {
		return errors.Wrap(err, "failed to delete secret")
	}
	return nil
}

// getNativeStore gets the native keychain store.
func (k *Keychain) getNativeStore() client.ProgramFunc {
	switch os := runtime.GOOS; os {
	case "linux":
		return client.NewShellProgramFunc("docker-credential-secretservice")
	case "darwin":
		return client.NewShellProgramFunc("docker-credential-osxkeychain")
	case "windows":
		return client.NewShellProgramFunc("docker-credential-wincred")
	default:
		return nil
	}
}
