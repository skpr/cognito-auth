package googleauth

import (
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"

	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/secrets"
)

// CreateLoginHandlerFileCache creates a login handler with a file cache.
func CreateLoginHandlerFileCache(cognitoConfig *config.Config, sess *session.Session, cacheDir string) *LoginHandler {
	tokensFileCache := oauth.NewFileCache(cacheDir)
	awscredsFileCache := awscreds.NewFileCache(cacheDir)
	return CreateLoginHandler(cognitoConfig, sess, tokensFileCache, awscredsFileCache)
}

// CreateLoginHandlerKeychainCache creates a login handler with a keychain cache.
func CreateLoginHandlerKeychainCache(cognitoConfig *config.Config, sess *session.Session, username string) *LoginHandler {
	keychain := secrets.NewKeychain(cognitoConfig.CredsOAuthKey, username)
	tokensKeychainCache := oauth.NewKeychainCache(keychain)
	awscredsKeychainCache := awscreds.NewKeychainCache(keychain)
	return CreateLoginHandler(cognitoConfig, sess, tokensKeychainCache, awscredsKeychainCache)
}

// CreateLoginHandler creates a login handler.
func CreateLoginHandler(cognitoConfig *config.Config,  sess client.ConfigProvider, tokenCache oauth.TokenCache, awscredsCache awscreds.CredentialsCache) *LoginHandler {
	tokensRefresher := NewTokensRefresher(cognitoConfig, tokenCache)
	tokensResolver := oauth.NewTokensResolver(tokenCache, tokensRefresher)
	cognitoIdentity := cognitoidentity.New(sess)
	credentialsResolver := awscreds.NewCredentialsResolver(cognitoConfig, awscredsCache, tokensResolver, cognitoIdentity)
	return  NewLoginHandler(cognitoConfig, tokenCache, credentialsResolver)
}
