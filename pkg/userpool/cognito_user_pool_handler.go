package userpool

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/config/cognito"
	"github.com/skpr/cognito-auth/pkg/credentials/aws"
	"github.com/skpr/cognito-auth/pkg/credentials/oauth"
	"time"
)

// CognitoUserPoolHandler handles cognito user pool functions.
type CognitoUserPoolHandler struct {
	CognitoConfig cognito.Config
	CognitoIdentityProvider cognitoidentityprovider.CognitoIdentityProvider
}

// Login logs in a user with username and password.
func (r *CognitoUserPoolHandler) Login(username string, password string) (oauth.Tokens, aws.ChallengeResponse, error) {

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeUserPasswordAuth)
	authInput.SetClientId(r.CognitoConfig.ClientID)

	authInput.SetAuthParameters(map[string]*string{
		"USERNAME": &username,
		"PASSWORD": &password,
	})
	authOutput, err := r.CognitoIdentityProvider.InitiateAuth(authInput)
	if err != nil {
		return oauth.Tokens{}, aws.ChallengeResponse{}, errors.Wrap(err, "Failed to login to identity provider")
	}

	if authOutput.ChallengeName != nil {
		challenge := aws.ChallengeResponse{
			Name:    *authOutput.ChallengeName,
			Session: *authOutput.Session,
		}
		return oauth.Tokens{}, challenge, nil
	}

	tokens := r.extractTokensFromAuthResult(authOutput.AuthenticationResult)

	return tokens, aws.ChallengeResponse{}, nil

}

// extractTokensFromAuthResult extracts oauth tokens from the authentication result.
func (r *CognitoUserPoolHandler) extractTokensFromAuthResult(authResult *cognitoidentityprovider.AuthenticationResultType) oauth.Tokens {
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
