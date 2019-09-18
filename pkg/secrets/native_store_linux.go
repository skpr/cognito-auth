package secrets

import "github.com/docker/docker-credential-helpers/credentials"
import "github.com/docker/docker-credential-helpers/secretservice"

// Gets the native store for darwin.
func GetNativeStore() credentials.Helper {
	return secretservice.Secretservice{}
}
