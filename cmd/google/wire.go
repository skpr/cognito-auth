//+build wireinject

package google

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/google/wire"
	"github.com/skpr/cognito-auth/pkg/secrets"
	"os/user"

	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/googleauth"
	"github.com/skpr/cognito-auth/pkg/oauth"
)

//go:generate wire

var providerSet = wire.NewSet(
	wire.Bind(new(oauth.TokensRefresher), new(*googleauth.TokensRefresher)),
	googleauth.NewTokensRefresher,
	oauth.NewTokensResolver,
	awscreds.NewCredentialsResolver,
	cognitoidentity.New,
	googleauth.NewLoginHandler,
)

// InitializeLoginHandlerFileCache initializes a LoginHandler with a file cache.
func InitializeLoginHandlerFileCache(cacheDir string, cognitoConfig *config.Config, sess *session.Session, awsConfig []*aws.Config) *googleauth.LoginHandler {
	wire.Build(
		wire.Bind(new(oauth.TokenCache), new(*oauth.FileCache)),
		oauth.NewFileCache,
		wire.Bind(new(awscreds.CredentialsCache), new(*awscreds.FileCache)),
		awscreds.NewFileCache,
		wire.Bind(new(client.ConfigProvider), new(*session.Session)),
		providerSet,
	)
	return &googleauth.LoginHandler{}
}

// InitializeLoginHandlerFileCache initializes a LoginHandler with a keychain cache.
func InitializeLoginHandlerKeychain(cognitoConfig *config.Config, sess *session.Session, awsConfig []*aws.Config, service string, user user.User) *googleauth.LoginHandler {
	wire.Build(
		secrets.NewKeychain,
		wire.Bind(new(client.ConfigProvider), new(*session.Session)),
		wire.Bind(new(oauth.TokenCache), new(*oauth.KeychainCache)),
		oauth.NewKeychainCache,
		wire.Bind(new(awscreds.CredentialsCache), new(*awscreds.KeychainCache)),
		awscreds.NewKeychainCache,
		providerSet,
	)
    return &googleauth.LoginHandler{}
}
