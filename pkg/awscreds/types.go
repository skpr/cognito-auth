package awscreds

// CredentialsCache defines an interface for credentials caches.
type CredentialsCache interface {
	Get() (Credentials, error)
	Put(credentials Credentials) error
	Delete(credentials Credentials) error
}
