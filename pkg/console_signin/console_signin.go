package console_signin

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/credentials_resolver"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

type ConsoleSignin struct {
	CredentialsResolver credentials_resolver.CredentialsResolver
}

// Creates a new credentials resolver.
func New(resolver credentials_resolver.CredentialsResolver) (ConsoleSignin, error) {
	return ConsoleSignin{
		CredentialsResolver: resolver,
	}, nil
}

// Gets the federated console sign in link.
func (c *ConsoleSignin) GetSignInLink() (string, error) {

	creds, err := c.CredentialsResolver.GetAwsCredentials()
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
