package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/skpr/cognito-auth/pkg/credentials_resolver"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdLogout struct {
	ConfigDir string
	Region string
}

func (v *cmdLogout) run(c *kingpin.ParseContext) error {
	config := aws.NewConfig().WithRegion(v.Region)
	sess, err := session.NewSession(config)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	resolver, err := credentials_resolver.New(v.ConfigDir, sess)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = resolver.Logout()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("You successfully logged out.")
	return nil
}

// Login sub-command.
func Logout(app *kingpin.Application) {
	v := new(cmdLogout)

	command := app.Command("logout", "Logs out a user.").Action(v.run)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
	}
	command.Flag("config-dir", "The config directory to use.").Default(homeDir + "/.config/skpr").StringVar(&v.ConfigDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
