package userpool

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
)

// TokensRefresher struct
type TokensRefresher struct {
	cognitoConfig           config.Config
	tokenCache              oauth.TokenCache
	cognitoIdentityProvider cognitoidentityprovider.CognitoIdentityProvider
}

// NewTokensRefresher creates a new tokens refresher.
func NewTokensRefresher(cognitoConfig *config.Config, tokenCache oauth.TokenCache, cognitoIdentityProvider *cognitoidentityprovider.CognitoIdentityProvider) *TokensRefresher {
	return &TokensRefresher{
		cognitoConfig:           *cognitoConfig,
		tokenCache:              tokenCache,
		cognitoIdentityProvider: *cognitoIdentityProvider,
	}
}

// RefreshOAuthTokens refreshes the oauth tokens, and saves them to file.
func (r *TokensRefresher) RefreshOAuthTokens(refreshToken string) (oauth.Tokens, error) {

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeRefreshTokenAuth)
	authInput.SetClientId(r.cognitoConfig.ClientID)
	authInput.SetAuthParameters(map[string]*string{
		cognitoidentityprovider.AuthFlowTypeRefreshToken: &refreshToken,
	})
	authOutput, err := r.cognitoIdentityProvider.InitiateAuth(authInput)
	if err != nil {
		return oauth.Tokens{}, errors.Wrap(err, "Failed to refresh oauth2 tokens")
	}

	tokens := extractTokensFromAuthResult(authOutput.AuthenticationResult)
	// We don't get a refresh token for a refresh auth request, so add it back.
	tokens.RefreshToken = refreshToken

	err = r.tokenCache.Put(tokens)
	if err != nil {
		return oauth.Tokens{}, errors.Wrap(err, "Failed to save tokens to cache")
	}

	return tokens, nil
}
