package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdLogin struct {
	Username string
	Password		string
	ClientID         string
}

func (v *cmdLogin) run(c *kingpin.ParseContext) error {
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println(err)
	}
	svc := cognitoidentityprovider.New(sess, aws.NewConfig().WithRegion("ap-southeast-2"))

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeUserPasswordAuth)
	authInput.SetClientId(v.ClientID)

	authParams := map[string]*string {
		"USERNAME" : &v.Username,
		"PASSWORD": &v.Password,
	}

	authInput.SetAuthParameters(authParams)
	authOutput, err := svc.InitiateAuth(authInput)

	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			switch awsErr.Code() {
			case cognitoidentityprovider.ErrCodePasswordResetRequiredException:
				fmt.Println("You are required to change your password.")
				fmt.Println("https://pnx.auth.ap-southeast-2.amazoncognito.com/login?response_type=code&client_id=1u6m5v0naeftt0409udaeck52t&redirect_uri=http://localhost")
			}
		}
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(authOutput.String())

	result := authOutput.AuthenticationResult
	accessToken := result.AccessToken

	userInput := new(cognitoidentityprovider.GetUserInput)
	userInput.SetAccessToken(*accessToken)
	userOutput, err := svc.GetUser(userInput)
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
	//clientSecret = command.Flag("client-secret", "ClientId for authentication").Required().Envar("SKPR_CLIENT_SECRET").String()
	command.Flag("client-id", "ClientId for authentication").Required().Envar("SKPR_CLIENT_ID").StringVar(&v.ClientID)
	command.Flag("username", "Username for authentication").Required().Envar("SKPR_USERNAME").StringVar(&v.Username)
	command.Flag("password", "Password for authentication").Required().Envar("SKPR_PASSWORD").StringVar(&v.Password)
}
