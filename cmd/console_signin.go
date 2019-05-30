package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/previousnext/login/pkg/console_signin"
	"github.com/previousnext/login/pkg/credentials_resolver"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdConsoleSignIn struct {
	ConfigDir string
}

func (v *cmdConsoleSignIn) run(c *kingpin.ParseContext) error {
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println(err)
	}
	resolver, err := credentials_resolver.New(v.ConfigDir, sess)
	if err != nil {
		fmt.Println(err)
	}
	signin,err := console_signin.New(resolver)
	if err != nil {
		fmt.Println(err)
	}
	link, err := signin.GetSignInLink()
	if err != nil {
		fmt.Println(err)
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
}
