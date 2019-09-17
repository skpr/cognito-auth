package userpool

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
)

// LoginHandler handles cognito user pool functions.
type LoginHandler struct {
	tokenCache              oauth.TokenCache
	cognitoConfig           config.Config
	cognitoIdentityProvider cognitoidentityprovider.CognitoIdentityProvider
	credentialsResolver     awscreds.CredentialsResolver
}

// NewLoginHandler creates a new login handler.
func NewLoginHandler(tokenCache oauth.TokenCache, cognitoConfig *config.Config, cognitoIdentityProvider *cognitoidentityprovider.CognitoIdentityProvider, credentialsResolver *awscreds.CredentialsResolver) LoginHandler {
	return LoginHandler{
		tokenCache:              tokenCache,
		cognitoConfig:           *cognitoConfig,
		cognitoIdentityProvider: *cognitoIdentityProvider,
		credentialsResolver:     *credentialsResolver,
	}
}

// Login logs in a user with username and password.
func (r *LoginHandler) Login(username string, password string) (awscreds.Credentials, ChallengeResponse, error) {

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeUserPasswordAuth)
	authInput.SetClientId(r.cognitoConfig.ClientID)

	authInput.SetAuthParameters(map[string]*string{
		"USERNAME": &username,
		"PASSWORD": &password,
	})
	authOutput, err := r.cognitoIdentityProvider.InitiateAuth(authInput)
	if err != nil {
		return awscreds.Credentials{}, ChallengeResponse{}, errors.Wrap(err, "Failed to login to identity provider")
	}

	if authOutput.ChallengeName != nil {
		challenge := ChallengeResponse{
			Name:    *authOutput.ChallengeName,
			Session: *authOutput.Session,
		}
		return awscreds.Credentials{}, challenge, nil
	}

	tokens := extractTokensFromAuthResult(authOutput.AuthenticationResult)

	err = r.tokenCache.Put(tokens)

	if err != nil {
		return awscreds.Credentials{}, ChallengeResponse{}, errors.Wrap(err, "Failed to save tokens to cache")
	}

	credentials, err := r.credentialsResolver.GetTempCredentials(tokens.IDToken)
	if err != nil {
		return awscreds.Credentials{}, ChallengeResponse{}, errors.Wrap(err, "Failed to get temporary credentials")
	}

	return credentials, ChallengeResponse{}, nil

}

// ChangePasswordChallenge responds to a change password challenge.
func (r *LoginHandler) ChangePasswordChallenge(username string, password string, sess string) (awscreds.Credentials, error) {

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
		return awscreds.Credentials{}, errors.Wrap(err, "Password challenge failed")
	}

	tokens := extractTokensFromAuthResult(output.AuthenticationResult)
	credentials, err := r.credentialsResolver.GetTempCredentials(tokens.IDToken)
	if err != nil {
		return awscreds.Credentials{}, errors.Wrap(err, "Failed to login to identity provider")
	}

	return credentials, nil
}
