package userpool

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/credentials/aws"
	"github.com/skpr/cognito-auth/pkg/oauth"
)

// LogoutHandler struct.
type LogoutHandler struct {
	credentialsCache        aws.CredentialsCache
	tokensCache             oauth.TokensCache
	tokensResolver          oauth.TokensResolver
	cognitoIdentityProvider cognitoidentityprovider.CognitoIdentityProvider
}

// NewLogoutHandler creates a logout handler.
func NewLogoutHandler(credentialsCache *aws.CredentialsCache, tokensCache *oauth.TokensCache, cognitoIdentityProvider *cognitoidentityprovider.CognitoIdentityProvider) *LogoutHandler {
	return &LogoutHandler{
		credentialsCache:        *credentialsCache,
		tokensCache:             *tokensCache,
		cognitoIdentityProvider: *cognitoIdentityProvider,
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

	err = r.credentialsCache.Delete()
	if err != nil {
		return err
	}
	err = r.tokensCache.Delete()
	if err != nil {
		return err
	}

	return nil
}
