package secrets

import (
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/docker/docker-credential-helpers/osxkeychain"
)

// Gets the native store for darwin.
func GetNativeStore() credentials.Helper {
	return osxkeychain.Osxkeychain{}
}
