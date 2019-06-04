package userpool

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"time"
)

// extractTokensFromAuthResult extracts oauth tokens from the authentication result.
func extractTokensFromAuthResult(authResult *cognitoidentityprovider.AuthenticationResultType) oauth.Tokens {
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
