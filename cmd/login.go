package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/skpr/cognito-auth/pkg/credentials/resolver"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdLogin struct {
	Username  string
	Password  string
	ConfigDir string
	Region string
}

func (v *cmdLogin) run(c *kingpin.ParseContext) error {

	config := aws.NewConfig().WithRegion(v.Region)
	sess, err := session.NewSession(config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	resolver, err := resolver.New(v.ConfigDir, sess)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	creds, err := resolver.Login(v.Username, v.Password)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(creds)
	fmt.Println("You successfully logged in.")
	return nil
}

// Login sub-command.
func Login(app *kingpin.Application) {
	v := new(cmdLogin)

	command := app.Command("login", "Logs in a user.").Action(v.run)
	command.Flag("username", "Username for authentication").Required().StringVar(&v.Username)
	command.Flag("password", "Password for authentication").Required().StringVar(&v.Password)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
	}
	command.Flag("config-dir", "The config directory to use.").Default(homeDir + "/.config/skpr").StringVar(&v.ConfigDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
