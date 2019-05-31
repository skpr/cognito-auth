package forgot

import (
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/config/cognito"
)

// Constants
const (
	CognitoConfigFile  = "cognito_config.yml"
)

// PasswordResetter type
type PasswordResetter struct {
	ConfigDir     string
	AwsSession    client.ConfigProvider
	CognitoConfig cognito.Config
}

// New creates a new password resetter.
func New(configDir string, sess client.ConfigProvider) (PasswordResetter, error) {
	cognitoConfig, err := cognito.LoadFromFile(configDir + "/" + CognitoConfigFile)
	if err != nil {
		return PasswordResetter{}, errors.Wrap(err, "Failed to load cognito config")
	}
	return PasswordResetter{
		ConfigDir:     configDir,
		AwsSession:    sess,
		CognitoConfig: cognitoConfig,
	}, nil
}

// InitResetPassword initiates the password reset flow.
func (r *PasswordResetter) InitResetPassword(username string) error {

	svc := cognitoidentityprovider.New(r.AwsSession)

	forgotPasswordInput := new(cognitoidentityprovider.ForgotPasswordInput)
	forgotPasswordInput.SetClientId(r.CognitoConfig.ClientID)
	forgotPasswordInput.SetUsername(username)

	_, err := svc.ForgotPassword(forgotPasswordInput)

	if err != nil {
		return errors.Wrap(err, "Failed to initiate password reset.")
	}

	return nil

}

// ConfirmResetPassword confirms the password reset.
func (r *PasswordResetter) ConfirmResetPassword(username string, password string, code string) error {

	svc := cognitoidentityprovider.New(r.AwsSession)

	input := cognitoidentityprovider.ConfirmForgotPasswordInput{
		ClientId: &r.CognitoConfig.ClientID,
		Username: &username,
		Password: &password,
		ConfirmationCode: &code,
	}

	_, err := svc.ConfirmForgotPassword(&input)

	if err != nil {
		return errors.Wrap(err, "Failed to confirm password reset.")
	}

	return nil

}