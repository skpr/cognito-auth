package oidc

import (
	"context"
	"fmt"
	"strconv"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"html/template"
	"net/http"

	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/rand"
)

const (
	scopes     = "openid email profile"
	successTpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Skpr Login</title>
<style>
* {
  font-family: Helvetica, sans-serif;
}
h1 {
  font-family: Georgia, serif;
  font-weight: 800;
}
pre,code {
  font-family: monospace;
  background-color: #eeeeee;
}
.container {
  display: flex;
  justify-content: center;
}
.center {
  min-width: 280px;
  margin-top: 100px;
}
</style>
</head>
<body>
<div class="container"><div class="center">
<a href="https://www.skpr.io"><svg width="138" height="49" viewBox="0 0 138 49"><g fill="#00170A" fill-rule="evenodd"><path d="M109.36 17.702c4.68 0 10.35 3.73 10.35 11.275 0 7.714-5.626 11.317-10.35 11.317-3.306 0-5.325-1.737-5.925-2.967v7.969c0 1.696-1.504 3.094-3.221 3.094-1.718 0-3.135-1.398-3.135-3.094V20.88c0-1.653 1.503-3.052 3.178-3.052 1.717 0 3.134 1.399 3.134 3.052v.17c.73-1.738 3.006-3.35 5.97-3.35zm25.65.186c1.932 0 2.92 1.314 2.92 2.84 0 1.695-1.331 2.882-3.994 2.882-3.22 0-5.196 2.416-5.325 3.9v9.79c0 1.654-1.417 3.053-3.134 3.053-1.718 0-3.135-1.4-3.135-3.052V21.109a3.14 3.14 0 013.135-3.136 3.141 3.141 0 013.134 3.136v1.695c.172-1.568 2.792-4.916 6.399-4.916zM60.839 10.03c3.693 0 5.84 1.272 7.643 2.967.945 1.06 1.417 1.865 1.417 2.84 0 1.399-1.073 2.5-2.662 2.5-.988 0-1.932-.508-2.534-1.186-1.116-1.102-2.018-1.61-3.606-1.61-2.362 0-3.607 1.313-3.607 2.924 0 1.102.558 2.289 3.006 3.264l1.417.508c7.042 2.628 9.575 5.172 9.575 9.114 0 6.018-6.054 8.943-11.036 8.943-3.263 0-6.698-1.23-8.931-3.645-.473-.551-1.375-1.695-1.375-3.137 0-1.314.86-2.67 2.62-2.67 1.417 0 2.362.89 3.049 1.78 1.503 1.653 3.177 2.12 4.594 2.12 1.89 0 4.466-.72 4.466-3.391 0-1.908-1.202-2.883-4.466-4.154l-1.545-.594c-4.466-1.695-7.858-3.772-7.858-8.223 0-5.171 4.38-8.35 9.833-8.35zm16.574-.297c1.718 0 3.135 1.4 3.135 3.095v13.309l7.772-7.418c.515-.508 1.332-.89 2.105-.89 1.588 0 2.834 1.314 2.834 2.798 0 .805-.258 1.483-.773 1.992l-5.712 5.17 7.172 7.885c.386.382.773 1.06.773 1.823 0 1.44-1.203 2.712-2.749 2.712-.773 0-1.503-.339-1.932-.847l-7.214-8.054-2.276 2.077v3.773c0 1.695-1.417 3.051-3.135 3.051-1.718 0-3.135-1.356-3.135-3.051v-24.33c0-1.696 1.417-3.095 3.135-3.095zm58.793 28.718l.708 1.35.708-1.35h.354v1.747h-.354v-1.125l-.56 1.125h-.286l-.57-1.125v1.125h-.344v-1.747h.344zm-.689 0v.311h-.668v1.436h-.344v-1.436h-.669v-.31h1.681zm-27.316-15.45c-2.147 0-5.067 1.525-5.067 5.976 0 4.493 2.92 6.019 5.067 6.019 2.62 0 5.239-2.035 5.239-6.02 0-3.941-2.62-5.975-5.24-5.975zm-74.035 2.521l-3.699 3.699c-4.57 4.569-11.788 5.716-17.227 2.227-7.638-4.899-8.438-15.223-2.402-21.26l3.998-3.997a3.418 3.418 0 00-4.833-4.833L6.005 5.356c-8.007 8.007-8.007 20.989 0 28.996 8.007 8.007 20.99 8.007 28.996 0L39 30.354a3.417 3.417 0 10-4.833-4.832"></path><path d="M23.665 17.748l-1.975 5.927c-.225.675-1.18.675-1.406 0l-.754-2.26a.74.74 0 00-.468-.47l-2.26-.753c-.676-.225-.676-1.18 0-1.406l5.926-1.975a.74.74 0 01.937.937m2.667-6.977h-5.859a9.113 9.113 0 109.113 9.113v-5.86a3.254 3.254 0 00-3.254-3.253" fill="#EE5622" fill-rule="nonzero"></path></g></svg></a>
<h1>Login Successful</h1>
<p>You have successfully logged in to Skpr.</p>
<p>Please return to the Skpr console.</p>
<pre><code>{{.}}</code></pre>
</div></div>
</body>
</html>
`
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
		AuthStyle: oauth2.AuthStyleInParams,
		AuthURL:   config.AuthURL,
		TokenURL:  config.TokenURL,
	}
	redirectURL := "http://localhost:" + strconv.Itoa(config.ListenPort)
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
	code, respState, err := l.getCode()
	if err != nil {
		return awscreds.Credentials{}, err
	}
	if state != respState {
		return awscreds.Credentials{}, errors.New("invalid state")
	}
	return l.Login(code)
}

// getCode starts an HTTP server to parse the OAuth2 callback and extract the code.
func (l *LoginHandler) getCode() (string, string, error) {
	var code, state string

	ctx, cancel := context.WithCancel(context.Background())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code = r.URL.Query().Get("code")
		state = r.URL.Query().Get("state")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl, _ := template.New("success").Parse(successTpl)
		_ = tmpl.Execute(w, code)

		cancel()
	})
	server := &http.Server{Addr: ":" + strconv.Itoa(l.cognitoConfig.ListenPort), Handler: handler}
	go func() {
		<-ctx.Done()
		fmt.Println("Shutting down the HTTP server...")
		_ = server.Shutdown(ctx)
	}()
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
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
