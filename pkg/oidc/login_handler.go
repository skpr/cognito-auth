package oidc

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/rand"
	"golang.org/x/oauth2"
	"net/http"
)

const (
	scopes      = "openid email profile"
	redirectURL = "http://localhost:8080"
)

// LoginHandler struct
type LoginHandler struct {
	cognitoConfig       config.Config
	oauth2Config        oauth2.Config
	tokensCache         oauth.TokenCache
	credentialsResolver awscreds.CredentialsResolver
}

// NewLoginHandler creates a new login handler
func NewLoginHandler(config *config.Config, tokensCache oauth.TokenCache, credentialsResolver *awscreds.CredentialsResolver) *LoginHandler {
	endpoint := oauth2.Endpoint{
		AuthStyle:oauth2.AuthStyleInParams,
		AuthURL: config.AuthURL,
		TokenURL: config.TokenURL,
	}
	return &LoginHandler{
		cognitoConfig: *config,
		oauth2Config: oauth2.Config{
			RedirectURL:  redirectURL,
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       []string{scopes},
			Endpoint:     endpoint,
		},
		tokensCache:         tokensCache,
		credentialsResolver: *credentialsResolver,
	}
}

// GetAuthCodeURL gets the authorisation code URL.
func (l *LoginHandler) GetAuthCodeURL() (string, string) {
	state := rand.String(8)
	return l.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline), state
}

// Handle handles the OAuth2 code flow.
func (l *LoginHandler) Handle(state string) (awscreds.Credentials, error) {
	code, respState, err := l.getCode(":8080")
	if err != nil {
		return awscreds.Credentials{}, err
	}
	if state != respState {
		return awscreds.Credentials{}, errors.New("invalid state")
	}
	return l.Login(code)
}

// getCode starts an HTTP server to parse the OAuth2 callback and extract the code.
func (l *LoginHandler) getCode(addr string) (string, string, error) {
	var code, state string

	ctx, cancel := context.WithCancel(context.Background())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code = r.URL.Query().Get("code")
		state = r.URL.Query().Get("state")
		cancel()
	})
	server := &http.Server{Addr: addr, Handler: handler}
	go func() {
		<-ctx.Done()
		fmt.Println("Shutting down the HTTP server...")
		_ = server.Shutdown(ctx)
	}()
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed{
		return "", "", err
	}
	return code, state, nil
}

// Login logs in a user with the authorization code.
func (l *LoginHandler) Login(code string) (awscreds.Credentials, error) {
	token, err := l.oauth2Config.Exchange(context.Background(), code)
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
