// +build unit

package oauth_tokens

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestSaveAndLoadFromFile(t *testing.T) {

	expiry := time.Now().Add(time.Duration(300 * time.Second)).Truncate(time.Duration(time.Second))

	tokens := OAuthTokens{
		AccessToken:  "ABCDEFGHIJKLMNOP1234567890",
		RefreshToken: "ABCDEFGHIJKLMNOP",
		IdToken:      "0123456789ABCDEF",
		Expiry:       expiry,
	}

	err := SaveToFile("/tmp/skpr/oauth_tokens.yml", tokens)
	assert.Nil(t, err)

	tokens, err = LoadFromFile("/tmp/skpr/oauth_tokens.yml")
	assert.Nil(t, err)

	assert.Equal(t, "ABCDEFGHIJKLMNOP1234567890", AccessToken, "access_token was set")
	assert.Equal(t, "ABCDEFGHIJKLMNOP", RefreshToken, "refresh_token was set")
	assert.Equal(t, "0123456789ABCDEF", IdToken, "id_token was set")
	assert.Equal(t, expiry, Expiry, "expiry was set")
}

func TestHasExpired(t *testing.T) {
	expiry := time.Now().Add(time.Duration(-300 * time.Second)).Truncate(time.Duration(time.Second))
	tokens := OAuthTokens{
		AccessToken:  "ABCDEFGHIJKLMNOP1234567890",
		RefreshToken: "ABCDEFGHIJKLMNOP",
		IdToken:      "0123456789ABCDEF",
		Expiry:       expiry,
	}

	assert.True(t, HasExpired())
}
