package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/googleauth"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"syscall"
)

type cmdGoogleLogin struct {
	Email      string
	ConfigFile string
	CacheDir   string
	Region     string
}

func (v *cmdGoogleLogin) run(c *kingpin.ParseContext) error {

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
	cognitoIdentity := cognitoidentity.New(sess)
	tokensRefresher := googleauth.NewTokensRefresher(&cognitoConfig, tokensCache)
	tokensResolver := oauth.NewTokensResolver(tokensCache, tokensRefresher)
	credentialsResolver := awscreds.NewCredentialsResolver(&cognitoConfig, credentialsCache, tokensResolver, cognitoIdentity)

	loginHandler := googleauth.NewLoginHandler(&cognitoConfig, tokensCache, credentialsResolver)
	authURL := loginHandler.GetAuthCodeURL()

	fmt.Println("Please login with the following link:")
	fmt.Println(authURL)
	fmt.Println("Then paste your authentication code:")
	bytecode, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Failed to read code: %v", err)
	}
	code := string(bytecode)

	creds, err := loginHandler.Login(code)

	fmt.Println(creds)

	return nil
}

// GoogleLogin sub-command.
func GoogleLogin(app *kingpin.Application) {
	v := new(cmdGoogleLogin)

	command := app.Command("google-login", "Logs in a user using their google account.").Action(v.run)
	homeDir, _ := os.UserHomeDir()
	cacheDir, _ := os.UserCacheDir()
	command.Flag("config-file", "The config file to use.").Default(homeDir + "/.config/cognito-auth/cognito_config.yml").StringVar(&v.ConfigFile)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").StringVar(&v.CacheDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
