package credentials_resolver

import (
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/aws_credentials"
	"github.com/skpr/cognito-auth/pkg/cognito_config"
	"github.com/skpr/cognito-auth/pkg/oauth_tokens"
	"time"
)

const (
	AwsCredentialsFile = "aws_credentials.yml"
	OAuthTokensFile    = "oauth_tokens.yml"
	CognitoConfigFile  = "cognito_config.yml"
)

type CredentialsResolver struct {
	ConfigDir     string
	AwsSession    client.ConfigProvider
	CognitoConfig cognito_config.CognitoConfig
}

// Creates a new credentials resolver.
func New(configDir string, sess client.ConfigProvider) (CredentialsResolver, error) {
	cognitoConfig, err := cognito_config.LoadFromFile(configDir + "/" + CognitoConfigFile)
	if err != nil {
		return CredentialsResolver{}, errors.Wrap(err, "Failed to load cognito config")
	}
	return CredentialsResolver{
		ConfigDir:     configDir,
		AwsSession:    sess,
		CognitoConfig: cognitoConfig,
	}, nil
}

// Login a user with username and password.
func (r *CredentialsResolver) Login(username string, password string) (aws_credentials.AwsCredentials, error) {

	cognitoIdentityProvider := cognitoidentityprovider.New(r.AwsSession)

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeUserPasswordAuth)
	authInput.SetClientId(r.CognitoConfig.ClientID)

	authInput.SetAuthParameters(map[string]*string{
		"USERNAME": &username,
		"PASSWORD": &password,
	})
	authOutput, err := cognitoIdentityProvider.InitiateAuth(authInput)
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Failed to login to identity provider")
	}

	tokens := r.extractTokensFromAuthResult(authOutput.AuthenticationResult)
	err = oauth_tokens.SaveToFile(r.ConfigDir+"/"+OAuthTokensFile, tokens)
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Could not save oauth tokens")
	}

	return r.getTempCredentialsForTokens(tokens)

}

// Logs out the current user.
func (r *CredentialsResolver) Logout() error {

	tokens, err := r.getOAuthTokens()
	if err != nil {
		return err
	}
	cognitoIdentityProvider := cognitoidentityprovider.New(r.AwsSession)
	signoutInput := cognitoidentityprovider.GlobalSignOutInput{
		AccessToken: &tokens.AccessToken,
	}
	_, err = cognitoIdentityProvider.GlobalSignOut(&signoutInput)
	if err != nil {
		return errors.Wrap(err, "Failed to sign out")
	}

	err = aws_credentials.Delete(r.ConfigDir+"/"+AwsCredentialsFile)
	if err != nil {
		return err
	}
	err = oauth_tokens.Delete(r.ConfigDir+"/"+OAuthTokensFile)
	if err != nil {
		return err
	}

	return nil
}

// Returns the AWS Credentials, refreshing if expired.
func (r *CredentialsResolver) GetAwsCredentials() (aws_credentials.AwsCredentials, error) {

	credentialsFile := r.ConfigDir + "/" + AwsCredentialsFile
	creds, err := aws_credentials.LoadFromFile(credentialsFile)
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Could not load aws credentials")
	}
	if creds.HasExpired() {
		creds, err = r.refreshAwsCredentials()
	}
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Could not refresh aws credentials")
	}

	return creds, nil
}

// Refreshes the AWS credentials.
func (r *CredentialsResolver) refreshAwsCredentials() (aws_credentials.AwsCredentials, error) {

	tokens, err := r.getOAuthTokens()
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Failed to load oauth tokens")
	}

	return r.getTempCredentialsForTokens(tokens)

}

// Get temporary STS AWS credentials for the oauth tokens, and save them.
func (r *CredentialsResolver) getTempCredentialsForTokens(tokens oauth_tokens.OAuthTokens) (aws_credentials.AwsCredentials, error) {
	identityService := cognitoidentity.New(r.AwsSession)

	logins := map[string]*string{
		r.CognitoConfig.UserPoolID: &tokens.IdToken,
	}
	idOutput, err := identityService.GetId(&cognitoidentity.GetIdInput{
		IdentityPoolId: &r.CognitoConfig.IdentityPoolID,
		Logins:         logins,
	})
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Failed to get cognito user id")
	}

	credsOutput, err := identityService.GetCredentialsForIdentity(&cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: idOutput.IdentityId,
		Logins:     logins,
	})
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Failed to get credentials for user id")
	}

	credentials := aws_credentials.AwsCredentials{
		AccessKey:       *credsOutput.Credentials.AccessKeyId,
		SecretAccessKey: *credsOutput.Credentials.SecretKey,
		SessionToken:    *credsOutput.Credentials.SessionToken,
		Expiry:          *credsOutput.Credentials.Expiration,
	}

	err = aws_credentials.SaveToFile(r.ConfigDir+"/"+AwsCredentialsFile, credentials)
	if err != nil {
		return aws_credentials.AwsCredentials{}, errors.Wrap(err, "Failed to save credentials to file")
	}

	return credentials, nil
}

// Gets the OAuth2 tokens, refreshing if expired.
func (r *CredentialsResolver) getOAuthTokens() (oauth_tokens.OAuthTokens, error) {
	tokens, err := oauth_tokens.LoadFromFile(r.ConfigDir + "/" + OAuthTokensFile)
	if err != nil {
		return oauth_tokens.OAuthTokens{}, errors.Wrap(err, "Could not load oauth tokens")
	}
	if tokens.HasExpired() {
		tokens, err = r.refreshOAuthTokens(tokens)
		err = oauth_tokens.SaveToFile(r.ConfigDir+"/"+OAuthTokensFile, tokens)
		if err != nil {
			return oauth_tokens.OAuthTokens{}, errors.Wrap(err, "Could not save oauth tokens")
		}
	}

	return tokens, nil
}

// Refreshes the oauth tokens, and saves them to file.
func (r *CredentialsResolver) refreshOAuthTokens(expiredTokens oauth_tokens.OAuthTokens) (oauth_tokens.OAuthTokens, error) {

	cognitoConfig, err := cognito_config.LoadFromFile(r.ConfigDir + "/" + CognitoConfigFile)

	cognitoIdentityProvider := cognitoidentityprovider.New(r.AwsSession)

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeRefreshTokenAuth)
	authInput.SetClientId(cognitoConfig.ClientID)
	authInput.SetAuthParameters(map[string]*string{
		cognitoidentityprovider.AuthFlowTypeRefreshToken: &expiredTokens.RefreshToken,
	})
	authOutput, err := cognitoIdentityProvider.InitiateAuth(authInput)
	if err != nil {
		return oauth_tokens.OAuthTokens{}, errors.Wrap(err, "Failed to refresh oauth2 tokens")
	}

	tokens := r.extractTokensFromAuthResult(authOutput.AuthenticationResult)
	// We don't get a refresh token for a refresh auth request, so add it back.
	tokens.RefreshToken = expiredTokens.RefreshToken

	err = oauth_tokens.SaveToFile(r.ConfigDir+"/"+OAuthTokensFile, tokens)
	if err != nil {
		return oauth_tokens.OAuthTokens{}, errors.Wrap(err, "Failed to save oauth2 tokens")
	}

	return tokens, nil
}

// Extract oauth tokens from the authentication result.
func (r *CredentialsResolver) extractTokensFromAuthResult(authResult *cognitoidentityprovider.AuthenticationResultType) oauth_tokens.OAuthTokens {
	ttl := time.Duration(*authResult.ExpiresIn * int64(time.Second))
	expiry := time.Now().Add(ttl).Truncate(time.Duration(time.Second))
	tokens := oauth_tokens.OAuthTokens{
		AccessToken:  *authResult.AccessToken,
		Expiry:       expiry,
		IdToken:      *authResult.IdToken,
	}
	if authResult.RefreshToken != nil {
		tokens.RefreshToken = *authResult.RefreshToken
	}
	return tokens
}
