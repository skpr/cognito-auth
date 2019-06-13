package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	awscredentials "github.com/skpr/cognito-auth/pkg/awscreds"
	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/userpool"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdLogout struct {
	ConfigFile string
	CacheDir   string
	Region     string
}

func (v *cmdLogout) run(c *kingpin.ParseContext) error {
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
	credentialsCache := awscredentials.NewCredentialsCache(v.CacheDir)
	cognitoIdentityProvider := cognitoidentityprovider.New(sess)
	tokensRefresher := userpool.NewTokensRefresher(&cognitoConfig, tokensCache, cognitoIdentityProvider)
	tokensResolver := oauth.NewTokensResolver(tokensCache, tokensRefresher)

	logoutHander := userpool.NewLogoutHandler(credentialsCache, tokensCache, tokensResolver, cognitoIdentityProvider)

	err = logoutHander.Logout()
	if err != nil {
		return err
	}

	fmt.Println("You successfully logged out.")
	return nil
}

// Logout sub-command.
func Logout(app *kingpin.Application) {
	v := new(cmdLogout)

	command := app.Command("logout", "Logs out a user.").Action(v.run)
	homeDir, _ := os.UserHomeDir()
	cacheDir, _ := os.UserCacheDir()
	command.Flag("config", "The config file to use.").Default(homeDir + "/.config/cognito-auth/userpool.yml").Envar("COGNITO_AUTH_CONFIG").StringVar(&v.ConfigFile)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").Envar("COGNITO_AUTH_CACHE_DIR").StringVar(&v.CacheDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").Envar("COGNITO_AUTH_REGION").StringVar(&v.Region)
}
