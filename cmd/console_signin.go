package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/consolesignin"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/secrets"
	"github.com/skpr/cognito-auth/pkg/userpool"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"os/user"
)

type cmdConsoleSignIn struct {
	ConfigFile string
	CacheDir   string
	CredsStore string
	Region     string
}

func (v *cmdConsoleSignIn) run(c *kingpin.ParseContext) error {
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

	if v.CredsStore == "native" {
		currentUser, err := user.Current()
		if err != nil {
			return err
		}
		oauth2Keychain := secrets.NewKeychain("Cognito OAuth2 Tokens", "http://example.com", currentUser.Username)
		tokenCache = oauth.NewKeychainCache(oauth2Keychain)
		awsCredsKeychain := secrets.NewKeychain("Cognito AWS Credentials", "http://example.com", currentUser.Username)
		credentialsCache = awscreds.NewKeychainCache(awsCredsKeychain)
	} else {
		tokenCache = oauth.NewFileCache(v.CacheDir)
		credentialsCache = awscreds.NewFileCache(v.CacheDir)
	}

	cognitoIdentityProvider := cognitoidentityprovider.New(sess)
	cognitoIdentity := cognitoidentity.New(sess)
	tokensRefresher := userpool.NewTokensRefresher(&cognitoConfig, tokenCache, cognitoIdentityProvider)
	tokensResolver := oauth.NewTokensResolver(tokenCache, tokensRefresher)

	credentialsResolver := awscreds.NewCredentialsResolver(&cognitoConfig, credentialsCache, tokensResolver, cognitoIdentity)
	signin := consolesignin.New(&cognitoConfig, credentialsResolver)

	link, err := signin.GetSignInLink()
	if err != nil {
		fmt.Println("Login required")
		return err
	}
	fmt.Println(link)

	return nil
}

// ConsoleSignIn console sign-in command.
func ConsoleSignIn(app *kingpin.Application) {
	v := new(cmdConsoleSignIn)
	command := app.Command("console-signin", "Generates a console sign-in link.").Action(v.run)
	homeDir, _ := os.UserHomeDir()
	cacheDir, _ := os.UserCacheDir()
	command.Flag("config", "The config file to use.").Default(homeDir + "/.config/cognito-auth/userpool.yml").Envar("COGNITO_AUTH_CONFIG").StringVar(&v.ConfigFile)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").Envar("COGNITO_AUTH_CACHE_DIR").StringVar(&v.CacheDir)
	command.Flag("creds-store", "The credentials store to use.").Default("file").Envar("COGNITO_AUTH_CREDS_STORE").StringVar(&v.CredsStore)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").Envar("COGNITO_AUTH_REGION").StringVar(&v.Region)
}
