package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/skpr/cognito-auth/pkg/console_signin"
	"github.com/skpr/cognito-auth/pkg/credentials_resolver"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdConsoleSignIn struct {
	ConfigDir string
	Region    string
}

func (v *cmdConsoleSignIn) run(c *kingpin.ParseContext) error {
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
	signin, err := console_signin.New(resolver)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	link, err := signin.GetSignInLink()
	if err != nil {
		fmt.Println(err)
		fmt.Println("Please login")
		os.Exit(1)
	}
	fmt.Println(link)

	return nil
}

// The console sign-in command.
func ConsoleSignIn(app *kingpin.Application) {
	v := new(cmdConsoleSignIn)
	command := app.Command("console-signin", "Generates a console sign-in link.").Action(v.run)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
	}
	command.Flag("config-dir", "The config directory to use.").Default(homeDir + "/.config/skpr").StringVar(&v.ConfigDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)

}
