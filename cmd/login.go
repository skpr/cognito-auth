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
	Username string
	Password string
	ClientID string
	IdentityPoolID string
	UserPoolID string
	Region string
}

func (v *cmdLogin) run(c *kingpin.ParseContext) error {
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println(err)
	}
	region := "ap-southeast-2"
	config := aws.NewConfig().WithRegion(region)
	cognitoIdentityProvider := cognitoidentityprovider.New(sess, config)

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeUserPasswordAuth)
	authInput.SetClientId(v.ClientID)

	authParams := map[string]*string{
		"USERNAME": &v.Username,
		"PASSWORD": &v.Password,
	}

	authInput.SetAuthParameters(authParams)
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
	getIdInput := cognitoidentity.GetIdInput{
		IdentityPoolId: &v.IdentityPoolID,
		Logins:         logins,
	}

	getIdOutput, err := identityService.GetId(&getIdInput)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	getCredsInput := cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: getIdOutput.IdentityId,
		Logins:     logins,
	}

	getCredsOutput, err := identityService.GetCredentialsForIdentity(&getCredsInput)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(getCredsOutput.String())

	userInput := new(cognitoidentityprovider.GetUserInput)
	userInput.SetAccessToken(*accessToken)
	userOutput, err := cognitoIdentityProvider.GetUser(userInput)
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
	command.Flag("region", "The AWS region").Required().StringVar(&v.Region)
}
