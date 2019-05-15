package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdLogin struct {
	Username       string
	Password       string
	ClientID       string
	IdentityPoolID string
	UserPoolID     string
	Region         string
}

func (v *cmdLogin) run(c *kingpin.ParseContext) error {
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println(err)
	}
	config := aws.NewConfig().WithRegion(v.Region)
	cognitoIdentityProvider := cognitoidentityprovider.New(sess, config)

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeUserPasswordAuth)
	authInput.SetClientId(v.ClientID)

	authInput.SetAuthParameters(map[string]*string{
		"USERNAME": &v.Username,
		"PASSWORD": &v.Password,
	})
	authOutput, err := cognitoIdentityProvider.InitiateAuth(authInput)

	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			switch awsErr.Code() {
			case cognitoidentityprovider.ErrCodePasswordResetRequiredException:
				fmt.Println("You are required to change your password.")
			}
		}
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(authOutput.String())

	result := authOutput.AuthenticationResult
	accessToken := result.AccessToken

	identityService := cognitoidentity.New(sess, config)

	logins := map[string]*string{
		v.UserPoolID: result.IdToken,
	}
	idOutput, err := identityService.GetId(&cognitoidentity.GetIdInput{
		IdentityPoolId: &v.IdentityPoolID,
		Logins:         logins,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(idOutput.String())

	credsOutput, err := identityService.GetCredentialsForIdentity(&cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: idOutput.IdentityId,
		Logins:     logins,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(credsOutput.String())

	userOutput, err := cognitoIdentityProvider.GetUser(&cognitoidentityprovider.GetUserInput{
		AccessToken: accessToken,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(userOutput.String())

	return nil
}

// Login sub-command.
func Login(app *kingpin.Application) {
	v := new(cmdLogin)

	command := app.Command("login", "Logs in a user.").Action(v.run)
	command.Flag("clientid", "Client ID for authentication").Required().StringVar(&v.ClientID)
	command.Flag("username", "Username for authentication").Required().StringVar(&v.Username)
	command.Flag("password", "Password for authentication").Required().StringVar(&v.Password)
	command.Flag("identity-pool-id", "The identity pool ID.").Required().StringVar(&v.IdentityPoolID)
	command.Flag("user-pool-id", "The user pool ID.").Required().StringVar(&v.UserPoolID)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
