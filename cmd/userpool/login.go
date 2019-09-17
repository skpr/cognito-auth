package userpool

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/userpool"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"os/user"
	"strings"
	"syscall"
)

type cmdLogin struct {
	Username   string
	Password   string
	ConfigFile string
	CacheDir   string
	CredsStore string
	Region     string
}

func (v *cmdLogin) run(c *kingpin.ParseContext) error {

	password := v.Password
	if password == "" {
		fmt.Print("Password: ")
		bytecode, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("Failed to read password")
			return err
		}
		password = string(bytecode)
		password = strings.TrimSpace(password)
		if password == "" {
			return errors.New("Password is required")
		}
		fmt.Println()
	}

	awsConfig := aws.NewConfig().WithRegion(v.Region)
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return err
	}

	cognitoConfig, err := config.Load(v.ConfigFile)
	if err != nil {
		return err
	}

	var tokenCache oauth.TokenCache
	tokenCache = oauth.NewFileCache(v.CacheDir)
	if v.CredsStore == "native" {
		currentUser, err := user.Current()
		if err != nil {
			return err
		}
		tokenCache = oauth.NewKeychainCache("Cognito Auth Credentials", "http://example.com/v1", currentUser.Username)
	}

	credentialsCache := awscreds.NewFileCache(v.CacheDir)

	cognitoIdentityProvider := cognitoidentityprovider.New(sess)
	cognitoIdentity := cognitoidentity.New(sess)
	tokensRefresher := userpool.NewTokensRefresher(&cognitoConfig, tokenCache, cognitoIdentityProvider)
	tokensResolver := oauth.NewTokensResolver(tokenCache, tokensRefresher)
	credentialsResolver := awscreds.NewCredentialsResolver(&cognitoConfig, credentialsCache, tokensResolver, cognitoIdentity)

	loginHandler := userpool.NewLoginHandler(tokenCache, &cognitoConfig, cognitoIdentityProvider, credentialsResolver)

	creds, challenge, err := loginHandler.Login(v.Username, password)
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
		newPassword := string(bytecode)
		newPassword = strings.TrimSpace(newPassword)

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

		if newPassword != confirmedPassword {
			fmt.Println()
			fmt.Println("Passwords do not match! Please try again.")
			return err
		}

		creds, err = loginHandler.ChangePasswordChallenge(v.Username, newPassword, challenge.Session)
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
func Login(c *kingpin.CmdClause) {
	v := new(cmdLogin)

	command := c.Command("login", "Logs in a user to a Cognito Userpool.").Action(v.run)

	command.Flag("username", "Username for authentication").Required().StringVar(&v.Username)
	command.Flag("password", "Password for authentication").StringVar(&v.Password)
	homeDir, _ := os.UserHomeDir()
	cacheDir, _ := os.UserCacheDir()
	command.Flag("config", "The config file to use.").Default(homeDir + "/.config/cognito-auth/userpool.yml").Envar("COGNITO_AUTH_CONFIG").StringVar(&v.ConfigFile)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").Envar("COGNITO_AUTH_CACHE_DIR").StringVar(&v.CacheDir)
	command.Flag("creds-store", "The credentials store to use.").Default("file").Envar("COGNITO_AUTH_CREDS_STORE").StringVar(&v.CredsStore)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").Envar("COGNITO_AUTH_REGION").StringVar(&v.Region)
}
