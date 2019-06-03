package resolver

import (
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/config/cognito"
	"github.com/skpr/cognito-auth/pkg/credentials/aws"
	"github.com/skpr/cognito-auth/pkg/credentials/oauth"
	"time"
)

// Constants
const (
	AwsCredentialsFile = "aws_credentials.yml"
	OAuthTokensFile    = "oauth_tokens.yml"
	CognitoConfigFile  = "cognito_config.yml"
)

// CredentialsResolver type
type CredentialsResolver struct {
	ConfigDir     string
	AwsSession    client.ConfigProvider
	CognitoConfig cognito.Config
}

// New creates a new credentials resolver.
func New(configDir string, sess client.ConfigProvider) (CredentialsResolver, error) {
	cognitoConfig, err := cognito.LoadFromFile(configDir + "/" + CognitoConfigFile)
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
func (r *CredentialsResolver) Login(username string, password string) (aws.Credentials, aws.ChallengeResponse, error) {

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
		return aws.Credentials{}, aws.ChallengeResponse{}, errors.Wrap(err, "Failed to login to identity provider")
	}

	if authOutput.ChallengeName != nil {
		challenge := aws.ChallengeResponse{
			Name:    *authOutput.ChallengeName,
			Session: *authOutput.Session,
		}
		return aws.Credentials{}, challenge, nil
	}

	tokens := r.extractTokensFromAuthResult(authOutput.AuthenticationResult)
	tokensCache := oauth.NewTokensCache(r.ConfigDir+"/"+OAuthTokensFile)
	err = tokensCache.Put(tokens)
	if err != nil {
		return aws.Credentials{}, aws.ChallengeResponse{}, errors.Wrap(err, "Could not save oauth tokens")
	}

	creds, err := r.getTempCredentialsForTokens(tokens)

	return creds, aws.ChallengeResponse{}, err

}

// ChangePasswordChallenge responds to a change password challenge.
func (r *CredentialsResolver) ChangePasswordChallenge(username string, password string, sess string) (aws.Credentials, error) {
	cognitoIdentityProvider := cognitoidentityprovider.New(r.AwsSession)
	challengeName := "NEW_PASSWORD_REQUIRED"
	challengeResponses := map[string]*string{
		"USERNAME":     &username,
		"NEW_PASSWORD": &password,
	}

	input := cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName:      &challengeName,
		ClientId:           &r.CognitoConfig.ClientID,
		Session:            &sess,
		ChallengeResponses: challengeResponses,
	}
	output, err := cognitoIdentityProvider.RespondToAuthChallenge(&input)
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Password challenge failed")
	}

	tokens := r.extractTokensFromAuthResult(output.AuthenticationResult)
	tokensCache := oauth.NewTokensCache(r.ConfigDir+"/"+OAuthTokensFile)
	err = tokensCache.Put(tokens)
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Could not save oauth tokens")
	}

	creds, err := r.getTempCredentialsForTokens(tokens)

	return creds, err
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

	credentialsCache := aws.NewCredentialsCache(r.ConfigDir + "/" + AwsCredentialsFile)
	err = credentialsCache.Delete()
	if err != nil {
		return err
	}
	tokensCache := oauth.NewTokensCache(r.ConfigDir+"/"+OAuthTokensFile)
	err = tokensCache.Delete()
	if err != nil {
		return err
	}

	return nil
}

// GetAwsCredentials returns the AWS Credentials, refreshing if expired.
func (r *CredentialsResolver) GetAwsCredentials() (aws.Credentials, error) {

	credentialsCache := aws.NewCredentialsCache(r.ConfigDir + "/" + AwsCredentialsFile)
	creds, err := credentialsCache.Get()
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Could not load aws credentials")
	}
	if creds.HasExpired() {
		creds, err = r.refreshAwsCredentials()
	}
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Could not refresh aws credentials")
	}

	return creds, nil
}

// refreshAwsCredentials refreshes the AWS credentials.
func (r *CredentialsResolver) refreshAwsCredentials() (aws.Credentials, error) {

	tokens, err := r.getOAuthTokens()
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Failed to load oauth tokens")
	}

	return r.getTempCredentialsForTokens(tokens)

}

// getTempCredentialsForTokens gets the temporary STS AWS credentials for the oauth tokens, and saves them.
func (r *CredentialsResolver) getTempCredentialsForTokens(tokens oauth.Tokens) (aws.Credentials, error) {
	identityService := cognitoidentity.New(r.AwsSession)

	logins := map[string]*string{
		r.CognitoConfig.UserPoolID: &tokens.IDToken,
	}
	idOutput, err := identityService.GetId(&cognitoidentity.GetIdInput{
		IdentityPoolId: &r.CognitoConfig.IdentityPoolID,
		Logins:         logins,
	})
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Failed to get cognito user id")
	}

	credsOutput, err := identityService.GetCredentialsForIdentity(&cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: idOutput.IdentityId,
		Logins:     logins,
	})
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Failed to get credentials for user id")
	}

	credentials := aws.Credentials{
		AccessKey:       *credsOutput.Credentials.AccessKeyId,
		SecretAccessKey: *credsOutput.Credentials.SecretKey,
		SessionToken:    *credsOutput.Credentials.SessionToken,
		Expiry:          *credsOutput.Credentials.Expiration,
	}

	credentialsCache := aws.NewCredentialsCache(r.ConfigDir + "/" + AwsCredentialsFile)
	err = credentialsCache.Put(credentials)
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Failed to save credentials to file")
	}

	return credentials, nil
}

// getOAuthTokens gets the OAuth2 tokens, refreshing if expired.
func (r *CredentialsResolver) getOAuthTokens() (oauth.Tokens, error) {
	tokensCache := oauth.NewTokensCache(r.ConfigDir+"/"+OAuthTokensFile)
	tokens, err := tokensCache.Get()
	if err != nil {
		return oauth.Tokens{}, errors.Wrap(err, "Could not load oauth tokens")
	}
	if tokens.HasExpired() {
		tokens, err = r.refreshOAuthTokens(tokens)
		err = tokensCache.Put(tokens)
		if err != nil {
			return oauth.Tokens{}, errors.Wrap(err, "Could not save oauth tokens")
		}
	}

	return tokens, nil
}

// refreshOAuthTokens refreshes the oauth tokens, and saves them to file.
func (r *CredentialsResolver) refreshOAuthTokens(expiredTokens oauth.Tokens) (oauth.Tokens, error) {

	cognitoConfig, err := cognito.LoadFromFile(r.ConfigDir + "/" + CognitoConfigFile)

	cognitoIdentityProvider := cognitoidentityprovider.New(r.AwsSession)

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeRefreshTokenAuth)
	authInput.SetClientId(cognitoConfig.ClientID)
	authInput.SetAuthParameters(map[string]*string{
		cognitoidentityprovider.AuthFlowTypeRefreshToken: &expiredTokens.RefreshToken,
	})
	authOutput, err := cognitoIdentityProvider.InitiateAuth(authInput)
	if err != nil {
		return oauth.Tokens{}, errors.Wrap(err, "Failed to refresh oauth2 tokens")
	}

	tokens := r.extractTokensFromAuthResult(authOutput.AuthenticationResult)
	// We don't get a refresh token for a refresh auth request, so add it back.
	tokens.RefreshToken = expiredTokens.RefreshToken

	tokensCache := oauth.NewTokensCache(r.ConfigDir+"/"+OAuthTokensFile)
	err = tokensCache.Put(tokens)
	if err != nil {
		return oauth.Tokens{}, errors.Wrap(err, "Failed to save oauth2 tokens")
	}

	return tokens, nil
}

// extractTokensFromAuthResult extracts oauth tokens from the authentication result.
func (r *CredentialsResolver) extractTokensFromAuthResult(authResult *cognitoidentityprovider.AuthenticationResultType) oauth.Tokens {
	ttl := time.Duration(*authResult.ExpiresIn * int64(time.Second))
	expiry := time.Now().Add(ttl).Truncate(time.Duration(time.Second))
	tokens := oauth.Tokens{
		AccessToken: *authResult.AccessToken,
		Expiry:      expiry,
		IDToken:     *authResult.IdToken,
	}
	if authResult.RefreshToken != nil {
		tokens.RefreshToken = *authResult.RefreshToken
	}
	return tokens
}
