package identitypool

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/config/cognito"
	"github.com/skpr/cognito-auth/pkg/credentials/aws"
)

// CognitoIdentityPoolHandler handles aws identity pool functions.
type CognitoIdentityPoolHandler struct {
	CognitoConfig cognito.Config
	CognitoIdentityService cognitoidentity.CognitoIdentity
}

// New creates a new instance.
func New(cognitoConfig cognito.Config, identityService cognitoidentity.CognitoIdentity) (CognitoIdentityPoolHandler, error) {
	return CognitoIdentityPoolHandler{
		CognitoConfig: cognitoConfig,
		CognitoIdentityService: identityService,
	}, nil
}

// GetTempCredentials gets the temporary STS AWS credentials for the oauth tokens, and saves them.
func (r *CognitoIdentityPoolHandler) GetTempCredentials(logins map[string]*string) (aws.Credentials, error) {

	idOutput, err := r.CognitoIdentityService.GetId(&cognitoidentity.GetIdInput{
		IdentityPoolId: &r.CognitoConfig.IdentityPoolID,
		Logins:         logins,
	})
	if err != nil {
		return aws.Credentials{}, errors.Wrap(err, "Failed to get cognito user id")
	}

	credsOutput, err := r.CognitoIdentityService.GetCredentialsForIdentity(&cognitoidentity.GetCredentialsForIdentityInput{
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

	return credentials, nil
}
