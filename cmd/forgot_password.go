package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdForgotPassword struct {
	Username string
	Password string
	ClientID string
}

func (v *cmdForgotPassword) run(c *kingpin.ParseContext) error {
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println(err)
	}
	svc := cognitoidentityprovider.New(sess, aws.NewConfig().WithRegion("ap-southeast-2"))

	forgotPasswordInput := new(cognitoidentityprovider.ForgotPasswordInput)
	forgotPasswordInput.SetClientId(v.ClientID)
	forgotPasswordInput.SetUsername(v.Username)

	forgotPasswordOutput, err := svc.ForgotPassword(forgotPasswordInput)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(forgotPasswordOutput.String())

	return nil
}

// ForgotPassword sub-command.
func ForgotPassword(app *kingpin.Application) {
	v := new(cmdForgotPassword)

	command := app.Command("forgot-password", "Starts the forgot password process.").Action(v.run)
	//clientSecret = command.Flag("client-secret", "ClientId for authentication").Required().Envar("SKPR_CLIENT_SECRET").String()
	command.Flag("client-id", "ClientId for reset").Required().StringVar(&v.ClientID)
	command.Flag("username", "Access token for change password").Required().StringVar(&v.Username)
}
