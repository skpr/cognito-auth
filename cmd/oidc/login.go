package oidc

import (
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
	"github.com/skratchdot/open-golang/open"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/skpr/cognito-auth/pkg/config"
	"github.com/skpr/cognito-auth/pkg/oidc"
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

	var loginHandler *oidc.LoginHandler
	if cognitoConfig.CredsStore == "native" {
		currentUser, err := user.Current()
		if err != nil {
			return err
		}
		loginHandler = oidc.CreateLoginHandlerKeychainCache(&cognitoConfig, sess, currentUser.Username)
	} else {
		loginHandler = oidc.CreateLoginHandlerFileCache(&cognitoConfig, sess, v.CacheDir)
	}

	authURL, state := loginHandler.GetAuthCodeURL()

	fmt.Println("You will now be taken to your browser to login.")
	time.Sleep(1 * time.Second)
	err = open.Run(authURL)
	if err != nil {
		return err
	}
	fmt.Println("Authentication URL:", authURL)

	creds, err := loginHandler.Handle(state)

	if err != nil {
		return errors.Wrap(err, "Failed to login")
	}

	fmt.Println(creds)

	return nil
}

// Login sub-command.
func Login(c *kingpin.CmdClause) {
	v := new(cmdLogin)

	command := c.Command("login", "Logs in a user using their OpenID Connect account.").Action(v.run)
	homeDir, _ := os.UserHomeDir()
	cacheDir, _ := os.UserCacheDir()
	command.Flag("config", "The config file to use.").Default(homeDir + "/.config/cognito-auth/oidc.yml").Envar("COGNITO_AUTH_CONFIG").StringVar(&v.ConfigFile)
	command.Flag("cache-dir", "The cache directory to use.").Default(cacheDir + "/cognito-auth").Envar("COGNITO_AUTH_CACHE_DIR").StringVar(&v.CacheDir)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").Envar("COGNITO_AUTH_REGION").StringVar(&v.Region)
}
