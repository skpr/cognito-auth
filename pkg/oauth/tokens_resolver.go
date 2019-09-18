package oauth

import "github.com/pkg/errors"

// TokensResolver struct
type TokensResolver struct {
	tokensCache     TokenCache
	tokensRefresher TokensRefresher
}

// NewTokensResolver creates a new tokens resolver.
func NewTokensResolver(tokensCache TokenCache, tokensRefresher TokensRefresher) *TokensResolver {
	return &TokensResolver{
		tokensCache:     tokensCache,
		tokensRefresher: tokensRefresher,
	}
}

// GetTokens gets the tokens, refreshing if needed.
func (r *TokensResolver) GetTokens() (Tokens, error) {
	tokens, err := r.tokensCache.Get()
	if err != nil {
		return Tokens{}, errors.Wrap(err, "Failed to get tokens from cache")
	}
	if !tokens.HasExpired() {
		return tokens, nil
	}
	tokens, err = r.tokensRefresher.RefreshOAuthTokens(tokens.RefreshToken)
	if err != nil {
		return Tokens{}, errors.Wrap(err, "Failed to refresh tokens")
	}
	err = r.tokensCache.Put(tokens)
	if err != nil {
		return Tokens{}, errors.Wrap(err, "Failed to save tokens to cache")
	}
	return tokens, nil
}
