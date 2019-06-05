package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/userpool"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"strings"
	"syscall"
)

type cmdLogin struct {
	Username   string
	Password   string
	ConfigFile string
	CacheDir   string
	Region     string
}

func (v *cmdLogin) run(c *kingpin.ParseContext) error {

	awsConfig := aws.NewConfig().WithRegion(v.Region)
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return err
	}

	cognitoConfig, err := config.Load(v.ConfigFile)
	if err != nil {
		return err
	}

	tokensCache := oauth.NewTokensCache(v.CacheDir)
	credentialsCache := awscreds.NewCredentialsCache(v.CacheDir)

	cognitoIdentityProvider := cognitoidentityprovider.New(sess)
	cognitoIdentity := cognitoidentity.New(sess)
	tokensRefresher := userpool.NewTokensRefresher(&cognitoConfig, tokensCache, cognitoIdentityProvider)
	tokensResolver := oauth.NewTokensResolver(tokensCache, tokensRefresher)
	credentialsResolver := awscreds.NewCredentialsResolver(&cognitoConfig, credentialsCache, tokensResolver, cognitoIdentity)

	loginHandler := userpool.NewLoginHandler(tokensCache, &cognitoConfig, cognitoIdentityProvider, credentialsResolver)

	creds, challenge, err := loginHandler.Login(v.Username, v.Password)
	if err != nil {
		return err
	}

	if challenge.Name == "NEW_PASSWORD_REQUIRED" {
		fmt.Println("You are required to change your password.")
		fmt.Print("Enter the new password: ")
		bytecode, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("Failed to read password")
			return err
		}
		password := string(bytecode)
		password = strings.TrimSpace(password)

		fmt.Println()
		fmt.Print("Confirm the new password: ")
		bytecode, err = terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println()
			fmt.Println("Failed to read password confirmation")
			return err
		}
		confirmedPassword := string(bytecode)
		confirmedPassword = strings.TrimSpace(confirmedPassword)

		if password != confirmedPassword {
			fmt.Println()
			fmt.Println("Passwords do not match! Please try again.")
			return err
		}

		creds, err = loginHandler.ChangePasswordChallenge(v.Username, password, challenge.Session)
		if err != nil {
			fmt.Println(err)
			return err
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
	homeDir, _ := os.UserHomeDir()
	cacheDir, _ := os.UserCacheDir()
	command.Flag("config-file", "The config file to use.").Default(homeDir + "/.config/cognito-auth/cognito_config.yml").StringVar(&v.ConfigFile)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").StringVar(&v.CacheDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
