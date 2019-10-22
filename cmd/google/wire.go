//+build wireinject

package google

//go:generate wire gen

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/google/wire"

	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/googleauth"
	"github.com/skpr/cognito-auth/pkg/oauth"
)

// InitializeLoginHandler initialises the login handler.
func InitializeLoginHandler(awsConfig *aws.Config, cognitoConfig *config.Config, cacheDir string) (googleauth.LoginHandler, error) {
	wire.Build(
		googleauth.NewLoginHandler,
		wire.InterfaceValue(new(oauth.TokenCache), oauth.NewFileCache),
		awscreds.NewCredentialsResolver,
		wire.InterfaceValue(new(awscreds.CredentialsCache), awscreds.NewFileCache),
		session.NewSession,
		cognitoidentity.New,
		googleauth.NewTokensRefresher,

	)
	return googleauth.LoginHandler{}, nil
}
