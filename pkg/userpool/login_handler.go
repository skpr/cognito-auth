package userpool

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/credentials/aws"
	"github.com/skpr/cognito-auth/pkg/oauth"
)

// LoginHandler handles cognito user pool functions.
type LoginHandler struct {
	tokensCache             oauth.TokensCache
	cognitoConfig           config.Config
	cognitoIdentityProvider cognitoidentityprovider.CognitoIdentityProvider
	credentialsResolver     aws.CredentialsResolver
}

// NewLoginHandler creates a new login handler.
func NewLoginHandler(tokensCache *oauth.TokensCache, cognitoConfig *config.Config, cognitoIdentityProvider *cognitoidentityprovider.CognitoIdentityProvider, credentialsResolver *aws.CredentialsResolver) LoginHandler {
	return LoginHandler{
		tokensCache:             *tokensCache,
		cognitoConfig:           *cognitoConfig,
		cognitoIdentityProvider: *cognitoIdentityProvider,
		credentialsResolver:     *credentialsResolver,
	}
}

// Login logs in a user with username and password.
func (r *LoginHandler) Login(username string, password string) (aws.Credentials, aws.ChallengeResponse, error) {

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeUserPasswordAuth)
	authInput.SetClientId(r.cognitoConfig.ClientID)

	authInput.SetAuthParameters(map[string]*string{
		"USERNAME": &username,
		"PASSWORD": &password,
	})
	authOutput, err := r.cognitoIdentityProvider.InitiateAuth(authInput)
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

	tokens := extractTokensFromAuthResult(authOutput.AuthenticationResult)

	err = r.tokensCache.Put(tokens)

	if err != nil {
		return aws.Credentials{}, aws.ChallengeResponse{}, errors.Wrap(err, "Failed to save tokens to cache")
	}

	credentials, err := r.credentialsResolver.GetTempCredentials(tokens.IDToken)
	if err != nil {
		return aws.Credentials{}, aws.ChallengeResponse{}, errors.Wrap(err, "Failed to get temporary credentials")
	}

	return credentials, aws.ChallengeResponse{}, nil

}

// ChangePasswordChallenge responds to a change password challenge.
func (r *LoginHandler) ChangePasswordChallenge(username string, password string, sess string) (aws.Credentials, error) {

	challengeName := "NEW_PASSWORD_REQUIRED"
	challengeResponses := map[string]*string{
		"USERNAME":     &username,
		"NEW_PASSWORD": &password,
	}

	input := cognitoidentityprovider.RespondToAuthChallengeInput{
		ChallengeName:      &challengeName,
		ClientId:           &r.cognitoConfig.ClientID,
		Session:            &sess,
		ChallengeResponses: challengeResponses,
	}
	output, err := r.cognitoIdentityProvider.RespondToAuthChallenge(&input)
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Password challenge failed")
	}

	tokens := extractTokensFromAuthResult(output.AuthenticationResult)
	credentials, err := r.credentialsResolver.GetTempCredentials(tokens.IDToken)
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Failed to login to identity provider")
	}

	return credentials, nil
}
