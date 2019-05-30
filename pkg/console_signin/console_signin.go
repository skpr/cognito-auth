package console_signin

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/pkg/errors"
	"github.com/previousnext/login/pkg/credentials_resolver"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

type ConsoleSignin struct {
	ConfigDir  string
	AwsSession client.ConfigProvider
}

// Gets the federated console sign in link.
func (c *ConsoleSignin) getSignInLink() (string, error) {

	resolver, err := credentials_resolver.New(c.ConfigDir, c.AwsSession)
	if err != nil {
		return "", errors.Wrap(err, "Failed creating credentials resolver")
	}

	creds, err := resolver.GetAwsCredentials()
	if err != nil {
		return "", errors.Wrap(err, "Failed getting credentials")
	}

	// Get console federated login link
	federationUrl := url.URL{
		Scheme: "https",
		Host:   "signin.aws.amazon.com",
		Path:   "/federation",
	}

	sessionParams := map[string]string{
		"sessionId":    creds.AccessKey,
		"sessionKey":   creds.SecretAccessKey,
		"sessionToken": creds.SessionToken,
	}
	jsonParams, _ := json.Marshal(sessionParams)

	query := federationUrl.Query()
	query.Add("Action", "getSigninToken")
	query.Add("SessionDuration", "43200")
	query.Add("Session", string(jsonParams))
	federationUrl.RawQuery = query.Encode()

	response, err := http.Get(federationUrl.String())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", errors.Wrap(err, "Failed getting response body")
	}

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
	query.Add("Issuer", "login.test.skpr.io")
	query.Add("Destination", "https://console.aws.amazon.com/cloudwatch")
	query.Add("SigninToken", signInToken)

	federationUrl.RawQuery = query.Encode()

	return federationUrl.String(), nil
}
