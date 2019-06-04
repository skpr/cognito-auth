package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/consolesignin"
	awscredentials "github.com/skpr/cognito-auth/pkg/credentials/aws"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/userpool"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdConsoleSignIn struct {
	ConfigDir string
	CacheDir  string
	Region    string
}

func (v *cmdConsoleSignIn) run(c *kingpin.ParseContext) error {
	awsConfig := aws.NewConfig().WithRegion(v.Region)
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return err
	}

	cognitoConfig, err := config.Load(v.ConfigDir)
	if err != nil {
		return err
	}

	tokensCache := oauth.NewTokensCache(v.CacheDir)
	credentialsCache := awscredentials.NewCredentialsCache(v.CacheDir)
	cognitoIdentityProvider := cognitoidentityprovider.New(sess)
	cognitoIdentity := cognitoidentity.New(sess)
	tokensRefresher := userpool.NewTokensRefresher(&cognitoConfig, tokensCache, cognitoIdentityProvider)
	tokensResolver := oauth.NewTokensResolver(tokensCache, tokensRefresher)

	credentialsResolver := awscredentials.NewCredentialsResolver(&cognitoConfig, credentialsCache, tokensResolver, cognitoIdentity)
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
	command.Flag("config-dir", "The config directory to use.").Default(homeDir + "/.config/cognito-auth").StringVar(&v.ConfigDir)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").StringVar(&v.CacheDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
