package google

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/googleauth"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/secrets"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"os/user"
	"syscall"
)

type cmdLogin struct {
	ConfigFile string
	CacheDir   string
	Region     string
}

func (v *cmdLogin) run(c *kingpin.ParseContext) error {

	awsConfig := aws.NewConfig().WithRegion(v.Region).WithCredentials(credentials.AnonymousCredentials)
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return err
	}

	cognitoConfig, err := config.Load(v.ConfigFile)
	if err != nil {
		return err
	}

	var tokenCache oauth.TokenCache
	var credentialsCache awscreds.CredentialsCache

	if cognitoConfig.CredsStore == "native" {
		currentUser, err := user.Current()
		if err != nil {
			return err
		}
		oauth2Keychain := secrets.NewKeychain(cognitoConfig.CredsOAuthKey, currentUser.Username)
		tokenCache = oauth.NewKeychainCache(oauth2Keychain)
		awsCredsKeychain := secrets.NewKeychain(cognitoConfig.CredsAwsKey, currentUser.Username)
		credentialsCache = awscreds.NewKeychainCache(awsCredsKeychain)
	} else {
		tokenCache = oauth.NewFileCache(v.CacheDir)
		credentialsCache = awscreds.NewFileCache(v.CacheDir)
	}

	cognitoIdentity := cognitoidentity.New(sess)
	tokensRefresher := googleauth.NewTokensRefresher(&cognitoConfig, tokenCache)
	tokensResolver := oauth.NewTokensResolver(tokenCache, tokensRefresher)
	credentialsResolver := awscreds.NewCredentialsResolver(&cognitoConfig, credentialsCache, tokensResolver, cognitoIdentity)

	loginHandler := googleauth.NewLoginHandler(&cognitoConfig, tokenCache, credentialsResolver)
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

	if err != nil {
		return errors.Wrap(err, "Failed to login")
	}

	fmt.Println(creds)

	return nil
}

// Login sub-command.
func Login(c *kingpin.CmdClause) {
	v := new(cmdLogin)

	command := c.Command("login", "Logs in a user using their google account.").Action(v.run)
	homeDir, _ := os.UserHomeDir()
	cacheDir, _ := os.UserCacheDir()
	command.Flag("config", "The config file to use.").Default(homeDir + "/.config/cognito-auth/google.yml").Envar("COGNITO_AUTH_CONFIG").StringVar(&v.ConfigFile)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").Envar("COGNITO_AUTH_CACHE_DIR").StringVar(&v.CacheDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").Envar("COGNITO_AUTH_REGION").StringVar(&v.Region)
}
