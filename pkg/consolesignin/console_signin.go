package consolesignin

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/skpr/cognito-auth/pkg/credentialsresolver"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

// ConsoleSignin type
type ConsoleSignin struct {
	CredentialsResolver credentialsresolver.CredentialsResolver
}

// New creates a new credentials resolver.
func New(resolver credentialsresolver.CredentialsResolver) (ConsoleSignin, error) {
	return ConsoleSignin{
		CredentialsResolver: resolver,
	}, nil
}

// GetSignInLink gets the federated console sign in link.
func (c *ConsoleSignin) GetSignInLink() (string, error) {

	creds, err := c.CredentialsResolver.GetAwsCredentials()
	if err != nil {
		return "", errors.Wrap(err, "Failed getting credentials")
	}

	// Get console federated login link
	federationURL := url.URL{
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

	query := federationURL.Query()
	query.Add("Action", "getSigninToken")
	query.Add("SessionDuration", "43200")
	query.Add("Session", string(jsonParams))
	federationURL.RawQuery = query.Encode()

	response, err := http.Get(federationURL.String())
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

	federationURL = url.URL{
		Scheme: "https",
		Host:   "signin.aws.amazon.com",
		Path:   "/federation",
	}

	query = federationURL.Query()
	query.Add("Action", "login")
	query.Add("Issuer", "login.test.skpr.io")
	query.Add("Destination", "https://console.aws.amazon.com/cloudwatch")
	query.Add("SigninToken", signInToken)

	federationURL.RawQuery = query.Encode()

	return federationURL.String(), nil
}
