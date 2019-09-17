package googleauth

import (
	"context"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	scopes      = "openid email"
	redirectURL = "urn:ietf:wg:oauth:2.0:oob"
)

// LoginHandler struct
type LoginHandler struct {
	cognitoConfig       config.Config
	googleConfig        oauth2.Config
	tokensCache         oauth.TokenCache
	credentialsResolver awscreds.CredentialsResolver
}

// NewLoginHandler creates a new login handler
func NewLoginHandler(config *config.Config, tokensCache oauth.TokenCache, credentialsResolver *awscreds.CredentialsResolver) *LoginHandler {
	return &LoginHandler{
		cognitoConfig: *config,
		googleConfig: oauth2.Config{
			RedirectURL:  redirectURL,
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       []string{scopes},
			Endpoint:     google.Endpoint,
		},
		tokensCache:         tokensCache,
		credentialsResolver: *credentialsResolver,
	}
}

// GetAuthCodeURL gets the authorisation code URL.
func (l *LoginHandler) GetAuthCodeURL() string {
	return l.googleConfig.AuthCodeURL("", oauth2.AccessTypeOffline)
}

// Login logs in a user with the authorization code.
func (l *LoginHandler) Login(code string) (awscreds.Credentials, error) {
	token, err := l.googleConfig.Exchange(context.Background(), code)
	if err != nil {
		return awscreds.Credentials{}, errors.Wrap(err, "Failed to login with code")
	}
	// Extract the ID Token from OAuth2 token.
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return awscreds.Credentials{}, errors.Wrap(err, "Missing id_token")
	}

	tokens := oauth.Tokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
		IDToken:      idToken,
	}

	err = l.tokensCache.Put(tokens)
	if err != nil {
		return awscreds.Credentials{}, errors.Wrap(err, "Failed to save tokens to cache")
	}

	credentials, err := l.credentialsResolver.GetTempCredentials(tokens.IDToken)
	if err != nil {
		return awscreds.Credentials{}, errors.Wrap(err, "Failed to get temporary credentials")
	}

	return credentials, nil
}
