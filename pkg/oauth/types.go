package oauth

// TokenCache defines the interface for token caches.
type TokenCache interface {
	Get() (Tokens, error)
	Put(token Tokens) error
	Delete(token Tokens) error
}
