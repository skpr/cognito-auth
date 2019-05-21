package cmd

import (
	"context"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"net/http"
	"os"
	"syscall"
)

type cmdGoogleLogin struct {
	Email          string
	ClientID       string
	ClientSecret   string
	IdentityPoolID string
	Region         string
}

func (v *cmdGoogleLogin) run(c *kingpin.ParseContext) error {

	googleOauthConfig := &oauth2.Config{
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		ClientID:     v.ClientID,
		ClientSecret: v.ClientSecret,
		Scopes:       []string{"openid email"},
		Endpoint:     google.Endpoint,
	}

	authUrl := googleOauthConfig.AuthCodeURL("", oauth2.AccessTypeOffline)

	fmt.Println("Please login with the following link:")
	fmt.Println(authUrl)
	fmt.Println("Then paste your authentication code:")
	bytecode, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Failed to read code: %v", err)
	}
	code := string(bytecode)

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		fmt.Println("Code exchange failed: %s", err.Error())
		os.Exit(1)
	}

	fmt.Println("Refresh token: " + token.RefreshToken)
	fmt.Println("Access token: " + token.AccessToken)
	fmt.Println("Token type: " + token.TokenType)
	fmt.Println("Expiry: " + token.Expiry.String())

	// Extract the ID Token from OAuth2 token.
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		fmt.Println("Missing id_token")
		os.Exit(1)
	}
	fmt.Println("ID token: " + idToken)

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		fmt.Println("Failed getting user info: %s", err.Error())
		os.Exit(1)
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Failed reading response body: %s", err.Error())
		os.Exit(1)
	}
	body := string(bodyBytes)
	fmt.Println("User info: " + body)

	return nil
}

// Login sub-command.
func GoogleLogin(app *kingpin.Application) {
	v := new(cmdGoogleLogin)

	command := app.Command("google-login", "Logs in a user.").Action(v.run)
	command.Flag("email", "The user email").Required().StringVar(&v.Email)
	command.Flag("client-id", "Client ID for authentication").Required().StringVar(&v.ClientID)
	command.Flag("client-secret", "Client secret for authentication").Required().StringVar(&v.ClientSecret)
	command.Flag("identity-pool-id", "The identity pool ID.").Required().StringVar(&v.IdentityPoolID)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
