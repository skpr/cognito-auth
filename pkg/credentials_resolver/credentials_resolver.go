package credentials_resolver

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/previousnext/login/pkg/credentials/aws_credentials"
	"github.com/previousnext/login/pkg/credentials/cognito_config"
	"github.com/previousnext/login/pkg/credentials/oauth_tokens"
	"time"
)

var (
	AwsCredentialsFile = "aws_credentials.yml"
	OAuthTokensFile    = "oauth_tokens.yml"
	CognitoConfigFile  = "cognito_config.yml"
	AwsRegion          = "ap-southeast-2"
)

type CredentialsResolver struct {
	ConfigDir string
}

func New(configDir string) (CredentialsResolver, error) {
	return CredentialsResolver{
		ConfigDir: configDir,
	}, nil
}

// Returns the AWS Credentials, refreshing if expired.
func (r *CredentialsResolver) GetAwsCredentials() (aws_credentials.AwsCredentials, error) {

	creds, err := aws_credentials.LoadFromFile(r.ConfigDir + "/" + AwsCredentialsFile)
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Could not load credentials")
	}
	if creds.HasExpired() {
		creds, err = r.RefreshAwsCredentials()
		aws_credentials.SaveToFile()
	}

	return creds, nil
}

// Refreshes the AWS credentials.
func (r *CredentialsResolver) RefreshAwsCredentials() (aws_credentials.AwsCredentials, error) {
	tokens, err := r.getOAuthTokens()
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Could not load oauth tokens")
	}

}

// Gets the OAuth2 tokens, refreshing if expired.
func (r *CredentialsResolver) getOAuthTokens() (oauth_tokens.OAuthTokens, error) {
	tokens, err := oauth_tokens.LoadFromFile(r.ConfigDir + "/" + OAuthTokensFile)
	if err != nil {
		return oauth_tokens.OAuthTokens{}, errors.Wrap(err, "Could not load oauth tokens")
	}
	if tokens.HasExpired() {
		tokens, err = r.refreshOAuthTokens(tokens)
	}

	return tokens, nil
}

func (r *CredentialsResolver) refreshOAuthTokens(expiredTokens oauth_tokens.OAuthTokens) (oauth_tokens.OAuthTokens, error) {

	cognitoConfig, err := cognito_config.LoadFromFile(r.ConfigDir + "/" + CognitoConfigFile)

	sess, err := session.NewSession()
	if err != nil {
		return oauth_tokens.OAuthTokens{}, errors.Wrap(err, "Failed to create session")
	}
	config := aws.NewConfig().WithRegion(AwsRegion)

	cognitoIdentityProvider := cognitoidentityprovider.New(sess, config)

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeRefreshTokenAuth)
	authInput.SetClientId(cognitoConfig.ClientID)
	authInput.SetAuthParameters(map[string]*string{
		cognitoidentityprovider.AuthFlowTypeRefreshToken: &expiredTokens.RefreshToken,
	})
	authOutput, err := cognitoIdentityProvider.InitiateAuth(authInput)

	ttl := time.Duration(*authOutput.AuthenticationResult.ExpiresIn * int64(time.Second))
	expiry := time.Now().Add(ttl).Truncate(time.Duration(time.Second))
	tokens := oauth_tokens.OAuthTokens{
		AccessToken: *authOutput.AuthenticationResult.AccessToken,
		Expiry: expiry,
		RefreshToken: *authOutput.AuthenticationResult.RefreshToken,
	}

	err = oauth_tokens.SaveToFile(r.ConfigDir + "/" + CognitoConfigFile, tokens)
	if err != nil {
		return oauth_tokens.OAuthTokens{}, errors.Wrap(err, "Failed to save oauth2 tokens")
	}

	return tokens, nil
}
