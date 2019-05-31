package credentialsresolver

import (
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/awscredentials"
	"github.com/skpr/cognito-auth/pkg/cognitoconfig"
	"github.com/skpr/cognito-auth/pkg/oauthtokens"
	"time"
)

// Constants
const (
	AwsCredentialsFile = "awscredentials.yml"
	OAuthTokensFile    = "oauthtokens.yml"
	CognitoConfigFile  = "cognitoconfig.yml"
)

// CredentialsResolver type
type CredentialsResolver struct {
	ConfigDir     string
	AwsSession    client.ConfigProvider
	CognitoConfig cognitoconfig.CognitoConfig
}

// New creates a new credentials resolver.
func New(configDir string, sess client.ConfigProvider) (CredentialsResolver, error) {
	cognitoConfig, err := cognitoconfig.LoadFromFile(configDir + "/" + CognitoConfigFile)
	if err != nil {
		return CredentialsResolver{}, errors.Wrap(err, "Failed to load cognito config")
	}
	return CredentialsResolver{
		ConfigDir:     configDir,
		AwsSession:    sess,
		CognitoConfig: cognitoConfig,
	}, nil
}

// Login logs in a user with username and password.
func (r *CredentialsResolver) Login(username string, password string) (awscredentials.AwsCredentials, error) {

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
		return awscredentials.AwsCredentials{}, errors.Wrap(err, "Failed to login to identity provider")
	}

	tokens := r.extractTokensFromAuthResult(authOutput.AuthenticationResult)
	err = oauthtokens.SaveToFile(r.ConfigDir+"/"+OAuthTokensFile, tokens)
	if err != nil {
		return awscredentials.AwsCredentials{}, errors.Wrap(err, "Could not save oauth tokens")
	}

	return r.getTempCredentialsForTokens(tokens)

}

// Logout logs out the current user.
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

	err = awscredentials.Delete(r.ConfigDir+"/"+AwsCredentialsFile)
	if err != nil {
		return err
	}
	err = oauthtokens.Delete(r.ConfigDir+"/"+OAuthTokensFile)
	if err != nil {
		return err
	}

	return nil
}

// GetAwsCredentials returns the AWS Credentials, refreshing if expired.
func (r *CredentialsResolver) GetAwsCredentials() (awscredentials.AwsCredentials, error) {

	credentialsFile := r.ConfigDir + "/" + AwsCredentialsFile
	creds, err := awscredentials.LoadFromFile(credentialsFile)
	if err != nil {
		return awscredentials.AwsCredentials{}, errors.Wrap(err, "Could not load aws credentials")
	}
	if creds.HasExpired() {
		creds, err = r.refreshAwsCredentials()
	}
	if err != nil {
		return awscredentials.AwsCredentials{}, errors.Wrap(err, "Could not refresh aws credentials")
	}

	return creds, nil
}

// refreshAwsCredentials refreshes the AWS credentials.
func (r *CredentialsResolver) refreshAwsCredentials() (awscredentials.AwsCredentials, error) {

	tokens, err := r.getOAuthTokens()
	if err != nil {
		return awscredentials.AwsCredentials{}, errors.Wrap(err, "Failed to load oauth tokens")
	}

	return r.getTempCredentialsForTokens(tokens)

}

// getTempCredentialsForTokens gets the temporary STS AWS credentials for the oauth tokens, and saves them.
func (r *CredentialsResolver) getTempCredentialsForTokens(tokens oauthtokens.OAuthTokens) (awscredentials.AwsCredentials, error) {
	identityService := cognitoidentity.New(r.AwsSession)

	logins := map[string]*string{
		r.CognitoConfig.UserPoolID: &tokens.IDToken,
	}
	idOutput, err := identityService.GetId(&cognitoidentity.GetIdInput{
		IdentityPoolId: &r.CognitoConfig.IdentityPoolID,
		Logins:         logins,
	})
	if err != nil {
		return awscredentials.AwsCredentials{}, errors.Wrap(err, "Failed to get cognito user id")
	}

	credsOutput, err := identityService.GetCredentialsForIdentity(&cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: idOutput.IdentityId,
		Logins:     logins,
	})
	if err != nil {
		return awscredentials.AwsCredentials{}, errors.Wrap(err, "Failed to get credentials for user id")
	}

	credentials := awscredentials.AwsCredentials{
		AccessKey:       *credsOutput.Credentials.AccessKeyId,
		SecretAccessKey: *credsOutput.Credentials.SecretKey,
		SessionToken:    *credsOutput.Credentials.SessionToken,
		Expiry:          *credsOutput.Credentials.Expiration,
	}

	err = awscredentials.SaveToFile(r.ConfigDir+"/"+AwsCredentialsFile, credentials)
	if err != nil {
		return awscredentials.AwsCredentials{}, errors.Wrap(err, "Failed to save credentials to file")
	}

	return credentials, nil
}

// getOAuthTokens gets the OAuth2 tokens, refreshing if expired.
func (r *CredentialsResolver) getOAuthTokens() (oauthtokens.OAuthTokens, error) {
	tokens, err := oauthtokens.LoadFromFile(r.ConfigDir + "/" + OAuthTokensFile)
	if err != nil {
		return oauthtokens.OAuthTokens{}, errors.Wrap(err, "Could not load oauth tokens")
	}
	if tokens.HasExpired() {
		tokens, err = r.refreshOAuthTokens(tokens)
		err = oauthtokens.SaveToFile(r.ConfigDir+"/"+OAuthTokensFile, tokens)
		if err != nil {
			return oauthtokens.OAuthTokens{}, errors.Wrap(err, "Could not save oauth tokens")
		}
	}

	return tokens, nil
}

// refreshOAuthTokens refreshes the oauth tokens, and saves them to file.
func (r *CredentialsResolver) refreshOAuthTokens(expiredTokens oauthtokens.OAuthTokens) (oauthtokens.OAuthTokens, error) {

	cognitoConfig, err := cognitoconfig.LoadFromFile(r.ConfigDir + "/" + CognitoConfigFile)

	cognitoIdentityProvider := cognitoidentityprovider.New(r.AwsSession)

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeRefreshTokenAuth)
	authInput.SetClientId(cognitoConfig.ClientID)
	authInput.SetAuthParameters(map[string]*string{
		cognitoidentityprovider.AuthFlowTypeRefreshToken: &expiredTokens.RefreshToken,
	})
	authOutput, err := cognitoIdentityProvider.InitiateAuth(authInput)
	if err != nil {
		return oauthtokens.OAuthTokens{}, errors.Wrap(err, "Failed to refresh oauth2 tokens")
	}

	tokens := r.extractTokensFromAuthResult(authOutput.AuthenticationResult)
	// We don't get a refresh token for a refresh auth request, so add it back.
	tokens.RefreshToken = expiredTokens.RefreshToken

	err = oauthtokens.SaveToFile(r.ConfigDir+"/"+OAuthTokensFile, tokens)
	if err != nil {
		return oauthtokens.OAuthTokens{}, errors.Wrap(err, "Failed to save oauth2 tokens")
	}

	return tokens, nil
}

// extractTokensFromAuthResult extracts oauth tokens from the authentication result.
func (r *CredentialsResolver) extractTokensFromAuthResult(authResult *cognitoidentityprovider.AuthenticationResultType) oauthtokens.OAuthTokens {
	ttl := time.Duration(*authResult.ExpiresIn * int64(time.Second))
	expiry := time.Now().Add(ttl).Truncate(time.Duration(time.Second))
	tokens := oauthtokens.OAuthTokens{
		AccessToken: *authResult.AccessToken,
		Expiry:      expiry,
		IDToken:     *authResult.IdToken,
	}
	if authResult.RefreshToken != nil {
		tokens.RefreshToken = *authResult.RefreshToken
	}
	return tokens
}
