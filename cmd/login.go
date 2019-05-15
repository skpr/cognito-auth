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
}

func (v *cmdLogin) run(c *kingpin.ParseContext) error {
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println(err)
	}
	config := aws.NewConfig().WithRegion("ap-southeast-2")
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


	//getCredsInput := cognitoidentity.GetCredentialsForIdentityInput{
	//	IdentityId:
	//}
	//
	//cognitoidentity.GetCredentialsForIdentity(getCredsInput)
	//{
	//identity_id: "IdentityId",
	//logins: {
	//	"IdentityProviderName" => "IdentityProviderToken",
	//},
	//custom_role_arn: "ARNString",
	//})

	//idToken := result.IdToken
	//sess.Config.WithCredentials(cognitoidentity.Credentials{
	//
	//})

	creds := new(cognitoidentity.Credentials)
	creds.SetSessionToken()
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
}
