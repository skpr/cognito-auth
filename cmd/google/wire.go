//+build wireinject

package google

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/google/wire"

	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/googleauth"
	"github.com/skpr/cognito-auth/pkg/oauth"
)

//go:generate wire

func InitializeLoginHandler(cacheDir string, cognitoConfig *config.Config, sess *session.Session, awsConfig []*aws.Config) *googleauth.LoginHandler {
	wire.Build(
		wire.Bind(new(oauth.TokenCache), new(*oauth.FileCache)),
		oauth.NewFileCache,
		wire.Bind(new(oauth.TokensRefresher), new(*googleauth.TokensRefresher)),
		googleauth.NewTokensRefresher,
		oauth.NewTokensResolver,
		wire.Bind(new(awscreds.CredentialsCache), new(*awscreds.FileCache)),
		awscreds.NewFileCache,
		awscreds.NewCredentialsResolver,
		wire.Bind(new(client.ConfigProvider), new(*session.Session)),
		cognitoidentity.New,
		googleauth.NewLoginHandler,
	)
	return &googleauth.LoginHandler{}
}
