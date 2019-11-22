package oidc

import (
	"context"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"golang.org/x/oauth2"
	"log"
)

// TokensRefresher struct
type TokensRefresher struct {
	cognitoConfig config.Config
	tokensCache   oauth.TokenCache
	oidcConfig    oauth2.Config
}

// NewTokensRefresher creates a new tokens refresher.
func NewTokensRefresher(cognitoConfig *config.Config, tokensCache oauth.TokenCache) *TokensRefresher {

	endpoint := oauth2.Endpoint{
		AuthURL:   cognitoConfig.AuthURL,
		TokenURL:  cognitoConfig.TokenURL,
		AuthStyle: oauth2.AuthStyleInParams,
	}

	return &TokensRefresher{
		cognitoConfig: *cognitoConfig,
		oidcConfig: oauth2.Config{
			RedirectURL:  redirectURL,
			ClientID:     cognitoConfig.ClientID,
			ClientSecret: cognitoConfig.ClientSecret,
			Scopes:       []string{scopes},
			Endpoint:     endpoint,
		},
		tokensCache: tokensCache,
	}
}

// RefreshOAuthTokens refreshes the oauth tokens, and saves them.
func (r *TokensRefresher) RefreshOAuthTokens(refreshToken string) (oauth.Tokens, error) {
	token := oauth2.Token{
		RefreshToken: refreshToken,
	}
	tokenSource := r.oidcConfig.TokenSource(context.Background(), &token)
	newToken, err := tokenSource.Token()
	if err != nil {
		log.Fatalln(err)
	}

	// Extract the ID Token from OAuth2 token.
	idToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		return oauth.Tokens{}, errors.Wrap(err, "Missing id_token")
	}

	tokens := oauth.Tokens{
		RefreshToken: refreshToken,
		AccessToken:  newToken.AccessToken,
		Expiry:       newToken.Expiry,
		IDToken:      idToken,
	}

	err = r.tokensCache.Put(tokens)
	if err != nil {
		return oauth.Tokens{}, errors.Wrap(err, "Failed to save tokens to cache")
	}

	return tokens, nil
}
