package cmd

import (
	"bufio"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/userpool"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"strings"
	"syscall"
)

type cmdResetPassword struct {
	Username   string
	ClientID   string
	ConfigFile string
	Region     string
}

func (v *cmdResetPassword) run(c *kingpin.ParseContext) error {

	awsConfig := aws.NewConfig().WithRegion(v.Region)
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cognitoConfig, err := config.Load(v.ConfigFile)
	if err != nil {
		return err
	}

	cognitoIdentityProvider := cognitoidentityprovider.New(sess)

	resetter := userpool.NewPasswordResetter(&cognitoConfig, cognitoIdentityProvider)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Are you sure you want to reset the password for ", v.Username, "? [y/n] ")
	text, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	text = strings.TrimSpace(text)

	if !strings.ContainsAny(text, "yY") {
		fmt.Println("Cancelled")
		os.Exit(0)
	}

	err = resetter.InitResetPassword(v.Username)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Please check your email for a password reset code.")
	fmt.Print("Enter the password reset code: ")

	code, _ := reader.ReadString('\n')
	code = strings.TrimSpace(code)
	if err != nil {
		fmt.Println(err)
		fmt.Println("Failed to read code")
		os.Exit(1)
	}

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

	err = resetter.ConfirmResetPassword(v.Username, password, code)
	if err != nil {
		fmt.Println(err)
		fmt.Println()
		fmt.Println("Failed to update password")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("Password successfully updated")

	return nil
}

// ResetPassword sub-command.
func ResetPassword(app *kingpin.Application) {
	v := new(cmdResetPassword)

	command := app.Command("reset-password", "Starts the reset password process.").Action(v.run)
	command.Flag("username", "The username").Required().StringVar(&v.Username)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
	}
	command.Flag("config-file", "The config file to use.").Default(homeDir + "/.config/cognito-auth/cognito_config.yml").StringVar(&v.ConfigFile)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
