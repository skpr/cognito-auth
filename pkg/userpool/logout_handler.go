package userpool

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/oauth"
)

// LogoutHandler struct.
type LogoutHandler struct {
	credentialsCache        awscreds.CredentialsCache
	credentialsResolver     awscreds.CredentialsResolver
	tokenCache              oauth.TokenCache
	tokensResolver          oauth.TokensResolver
	cognitoIdentityProvider cognitoidentityprovider.CognitoIdentityProvider
}

// NewLogoutHandler creates a logout handler.
func NewLogoutHandler(credentialsCache awscreds.CredentialsCache, tokenCache oauth.TokenCache, tokensResolver *oauth.TokensResolver, cognitoIdentityProvider *cognitoidentityprovider.CognitoIdentityProvider) *LogoutHandler {
	return &LogoutHandler{
		credentialsCache:        credentialsCache,
		tokenCache:              tokenCache,
		cognitoIdentityProvider: *cognitoIdentityProvider,
		tokensResolver:          *tokensResolver,
	}
}

// Logout logs out the current user.
func (r *LogoutHandler) Logout() error {
	tokens, err := r.tokensResolver.GetTokens()
	if err != nil {
		return err
	}
	signoutInput := cognitoidentityprovider.GlobalSignOutInput{
		AccessToken: &tokens.AccessToken,
	}
	_, err = r.cognitoIdentityProvider.GlobalSignOut(&signoutInput)
	if err != nil {
		return errors.Wrap(err, "Failed to sign out")
	}

	err = r.credentialsCache.Delete(awscreds.Credentials{})
	if err != nil {
		return err
	}
	err = r.tokenCache.Delete(tokens)
	if err != nil {
		return err
	}

	return nil
}
