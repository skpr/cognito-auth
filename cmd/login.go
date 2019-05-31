package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/skpr/cognito-auth/pkg/credentials/resolver"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"strings"
	"syscall"
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

	creds, challenge, err := resolver.Login(v.Username, v.Password)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if challenge.Name == "NEW_PASSWORD_REQUIRED" {
		fmt.Println("You are required to change your password.")
		fmt.Print("Enter the new password: ")
		bytecode, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println(err)
			fmt.Println("Failed to read password")
			os.Exit(1)
		}
		password := string(bytecode)
		password = strings.TrimSpace(password)

		fmt.Println()
		fmt.Print("Confirm the new password: ")
		bytecode, err = terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println(err)
			fmt.Println()
			fmt.Println("Failed to read password confirmation")
			os.Exit(1)
		}
		confirmedPassword := string(bytecode)
		confirmedPassword = strings.TrimSpace(confirmedPassword)

		if password != confirmedPassword {
			fmt.Println()
			fmt.Println("Passwords do not match! Please try again.")
			os.Exit(1)
		}

		creds, err = resolver.ChangePasswordChallenge(v.Username, password, challenge.Session)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println("Successfully changed password.")

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
