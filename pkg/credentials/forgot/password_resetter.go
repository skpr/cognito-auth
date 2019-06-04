package forgot

import (
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/config"
)

// PasswordResetter type
type PasswordResetter struct {
	CognitoConfig    config.Config
	identityProvider cognitoidentityprovider.CognitoIdentityProvider
}

// NewPasswordResetter creates a new password resetter.
func NewPasswordResetter(cognitoConfig *config.Config, identityProvider *cognitoidentityprovider.CognitoIdentityProvider) *PasswordResetter {
	return &PasswordResetter{
		CognitoConfig:    *cognitoConfig,
		identityProvider: *identityProvider,
	}
}

// InitResetPassword initiates the password reset flow.
func (r *PasswordResetter) InitResetPassword(username string) error {

	forgotPasswordInput := &cognitoidentityprovider.ForgotPasswordInput{
		ClientId: &r.CognitoConfig.ClientID,
		Username: &username,
	}

	_, err := r.identityProvider.ForgotPassword(forgotPasswordInput)

	if err != nil {
		return errors.Wrap(err, "Failed to initiate password reset.")
	}

	return nil

}

// ConfirmResetPassword confirms the password reset.
func (r *PasswordResetter) ConfirmResetPassword(username string, password string, code string) error {

	input := &cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId:         &r.CognitoConfig.ClientID,
		Username:         &username,
		Password:         &password,
		ConfirmationCode: &code,
	}

	_, err := r.identityProvider.ConfirmForgotPassword(input)

	if err != nil {
		return errors.Wrap(err, "Failed to confirm password reset.")
	}

	return nil

}
