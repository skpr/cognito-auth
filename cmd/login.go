package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

type cmdLogin struct {
	Username       string
	Password       string
	ClientID       string
	IdentityPoolID string
	UserPoolID     string
	Region         string
}

type Bird struct {
	Species string
	Description string
}

func (v *cmdLogin) run(c *kingpin.ParseContext) error {
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println(err)
	}
	config := aws.NewConfig().WithRegion(v.Region)

	cognitoIdentityProvider := cognitoidentityprovider.New(sess, config)

	authInput := new(cognitoidentityprovider.InitiateAuthInput)
	authInput.SetAuthFlow(cognitoidentityprovider.AuthFlowTypeUserPasswordAuth)
	authInput.SetClientId(v.ClientID)

	authInput.SetAuthParameters(map[string]*string{
		"USERNAME": &v.Username,
		"PASSWORD": &v.Password,
	})
	authOutput, err := cognitoIdentityProvider.InitiateAuth(authInput)

	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			switch awsErr.Code() {
			case cognitoidentityprovider.ErrCodePasswordResetRequiredException:
				fmt.Println("You are required to change your password.")
			}
		}
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(authOutput.String())

	result := authOutput.AuthenticationResult
	accessToken := result.AccessToken

	identityService := cognitoidentity.New(sess, config)

	logins := map[string]*string{
		v.UserPoolID: result.IdToken,
	}
	idOutput, err := identityService.GetId(&cognitoidentity.GetIdInput{
		IdentityPoolId: &v.IdentityPoolID,
		Logins:         logins,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(idOutput.String())

	creds, err := identityService.GetCredentialsForIdentity(&cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: idOutput.IdentityId,
		Logins:     logins,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(creds.String())

	userOutput, err := cognitoIdentityProvider.GetUser(&cognitoidentityprovider.GetUserInput{
		AccessToken: accessToken,
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(userOutput.String())

	// Get console federated login link
	federationUrl := url.URL{
		Scheme: "https",
		Host:   "signin.aws.amazon.com",
		Path:   "/federation",
	}

	sessionParams := map[string]string{
		"sessionId":    *creds.Credentials.AccessKeyId,
		"sessionKey":   *creds.Credentials.SecretKey,
		"sessionToken": *creds.Credentials.SessionToken,
	}
	jsonParams, _ := json.Marshal(sessionParams)

	query := federationUrl.Query()
	query.Add("Action", "getSigninToken")
	query.Add("SessionDuration", "43200")
	query.Add("Session", string(jsonParams))
	federationUrl.RawQuery = query.Encode()

	fmt.Println()
	fmt.Println(federationUrl.String())

	response, err := http.Get(federationUrl.String())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Failed reading response body: %s", err.Error())
		os.Exit(1)
	}
	body := string(bodyBytes)

	fmt.Println()
	fmt.Println(body)

	data := map[string]string{}
	err = json.Unmarshal(bodyBytes, &data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	signInToken := data["SigninToken"]

	federationUrl = url.URL{
		Scheme: "https",
		Host:   "signin.aws.amazon.com",
		Path:   "/federation",
	}

	query = federationUrl.Query()
	query.Add("Action", "login")
	query.Add("Issuer", "example.com")
	query.Add("Destination", "https://console.aws.amazon.com/cloudwatch")
	query.Add("SigninToken", signInToken)

	federationUrl.RawQuery = query.Encode()

	fmt.Println()
	fmt.Println(federationUrl.String())

	response, err = http.Get(federationUrl.String())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer response.Body.Close()
	bodyBytes, err = ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Failed reading response body: %s", err.Error())
		os.Exit(1)
	}
	body = string(bodyBytes)
	fmt.Println()
	fmt.Println(body)

	return nil
}

// Login sub-command.
func Login(app *kingpin.Application) {
	v := new(cmdLogin)

	command := app.Command("login", "Logs in a user.").Action(v.run)
	command.Flag("clientid", "Client ID for authentication").Required().StringVar(&v.ClientID)
	command.Flag("username", "Username for authentication").Required().StringVar(&v.Username)
	command.Flag("password", "Password for authentication").Required().StringVar(&v.Password)
	command.Flag("identity-pool-id", "The identity pool ID.").Required().StringVar(&v.IdentityPoolID)
	command.Flag("user-pool-id", "The user pool ID.").Required().StringVar(&v.UserPoolID)
	command.Flag("region", "The AWS region").Default("ap-southeast-2").StringVar(&v.Region)
}
