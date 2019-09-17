package userpool

import (
	"fmt"
	"os"
	"os/user"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	awscredentials "github.com/skpr/cognito-auth/pkg/awscreds"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/userpool"
)

type cmdLogout struct {
	ConfigFile string
	CacheDir   string
	Region     string
	CredsStore string
	Username   string
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

	var tokenCache oauth.TokenCache
	tokenCache = oauth.NewFileCache(v.CacheDir)
	if v.CredsStore == "native" {
		currentUser, err := user.Current()
		if err != nil {
			return err
		}
		tokenCache = oauth.NewKeychainCache("Cognito Auth Credentials", "http://example.com/v1", currentUser.Username)
	}
	credentialsCache := awscredentials.NewFileCache(v.CacheDir)
	cognitoIdentityProvider := cognitoidentityprovider.New(sess)
	tokensRefresher := userpool.NewTokensRefresher(&cognitoConfig, tokenCache, cognitoIdentityProvider)
	tokensResolver := oauth.NewTokensResolver(tokenCache, tokensRefresher)

	logoutHander := userpool.NewLogoutHandler(credentialsCache, tokenCache, tokensResolver, cognitoIdentityProvider)

	err = logoutHander.Logout()
	if err != nil {
		return err
	}

	fmt.Println("You successfully logged out.")
	return nil
}

// Logout sub-command.
func Logout(c *kingpin.CmdClause) {
	v := new(cmdLogout)

	command := c.Command("logout", "Logs out a user from a Cognito Userpool").Action(v.run)
	homeDir, _ := os.UserHomeDir()
	cacheDir, _ := os.UserCacheDir()
	command.Flag("config", "The config file to use.").Default(homeDir + "/.config/cognito-auth/userpool.yml").Envar("COGNITO_AUTH_CONFIG").StringVar(&v.ConfigFile)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").Envar("COGNITO_AUTH_CACHE_DIR").StringVar(&v.CacheDir)
	command.Flag("creds-store", "The credentials store to use.").Default("file").Envar("COGNITO_AUTH_CREDS_STORE").StringVar(&v.CredsStore)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").Envar("COGNITO_AUTH_REGION").StringVar(&v.Region)
}
