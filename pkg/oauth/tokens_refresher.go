package oauth

// TokensRefresher interface
type TokensRefresher interface {
	// refreshOAuthTokens refreshes the oauth tokens, and saves them to file.
	RefreshOAuthTokens(refreshToken string) (Tokens, error)
}
