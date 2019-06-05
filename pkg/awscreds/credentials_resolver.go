package awscreds

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
)

// CredentialsResolver struct
type CredentialsResolver struct {
	cognitoConfig    config.Config
	credentialsCache CredentialsCache
	tokensResolver   oauth.TokensResolver
	cognitoIdentity  cognitoidentity.CognitoIdentity
}

// NewCredentialsResolver creates a new credentials resolver.
func NewCredentialsResolver(cognitoConfig *config.Config, credentialsCache *CredentialsCache, tokensResolver *oauth.TokensResolver, cognitoIdentity *cognitoidentity.CognitoIdentity) *CredentialsResolver {
	return &CredentialsResolver{
		cognitoConfig:    *cognitoConfig,
		credentialsCache: *credentialsCache,
		tokensResolver:   *tokensResolver,
		cognitoIdentity:  *cognitoIdentity,
	}
}

// GetAwsCredentials returns the AWS Credentials, refreshing if expired.
func (r *CredentialsResolver) GetAwsCredentials() (Credentials, error) {

	creds, err := r.credentialsCache.Get()
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Could not load awscreds credentials")
	}
	if creds.HasExpired() {
		creds, err = r.RefreshAwsCredentials()
	}
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Could not refresh awscreds credentials")
	}

	return creds, nil
}

// RefreshAwsCredentials refreshes the AWS credentials.
func (r *CredentialsResolver) RefreshAwsCredentials() (Credentials, error) {

	tokens, err := r.tokensResolver.GetTokens()
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Failed to load oauth tokens")
	}

	return r.GetTempCredentials(tokens.IDToken)

}

// GetTempCredentials gets the temporary STS AWS credentials for the oauth tokens, and saves them.
func (r *CredentialsResolver) GetTempCredentials(idToken string) (Credentials, error) {

	logins := map[string]*string{
		r.cognitoConfig.IdentityProviderID: &idToken,
	}
	idOutput, err := r.cognitoIdentity.GetId(&cognitoidentity.GetIdInput{
		IdentityPoolId: &r.cognitoConfig.IdentityPoolID,
		Logins:         logins,
	})
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Failed to get cognito user id")
	}

	credsOutput, err := r.cognitoIdentity.GetCredentialsForIdentity(&cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: idOutput.IdentityId,
		Logins:     logins,
	})
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Failed to get credentials for user id")
	}

	credentials := Credentials{
		AccessKey:       *credsOutput.Credentials.AccessKeyId,
		SecretAccessKey: *credsOutput.Credentials.SecretKey,
		SessionToken:    *credsOutput.Credentials.SessionToken,
		Expiry:          *credsOutput.Credentials.Expiration,
	}

	err = r.credentialsCache.Put(credentials)
	if err != nil {
		return Credentials{}, errors.Wrap(err, "Failed to save credentials to file")
	}

	return credentials, nil
}
