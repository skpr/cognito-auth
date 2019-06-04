package cmd

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	awscredentials "github.com/skpr/cognito-auth/pkg/credentials/aws"
	"github.com/skpr/cognito-auth/pkg/oauth"
	"github.com/skpr/cognito-auth/pkg/userpool"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
)

type cmdLogout struct {
	ConfigDir string
	CacheDir  string
	Region    string
}

func (v *cmdLogout) run(c *kingpin.ParseContext) error {
	config := aws.NewConfig().WithRegion(v.Region)
	sess, err := session.NewSession(config)
	if err != nil {
		return err
	}
	tokensCache := oauth.NewTokensCache(v.CacheDir)
	credentialsCache := awscredentials.NewCredentialsCache(v.CacheDir)
	cognitoIdentityProvider := cognitoidentityprovider.New(sess)

	logoutHander := userpool.NewLogoutHandler(credentialsCache, tokensCache, cognitoIdentityProvider)

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
	command.Flag("config-dir", "The config directory to use.").Default(homeDir + "/.config/cognito-auth").StringVar(&v.ConfigDir)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").StringVar(&v.CacheDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
