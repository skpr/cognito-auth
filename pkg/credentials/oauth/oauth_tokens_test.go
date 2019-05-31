package oauth

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestSaveAndLoadFromFile(t *testing.T) {

	expiry := time.Now().Add(time.Duration(300 * time.Second)).Truncate(time.Duration(time.Second))

	tokens := Tokens{
		AccessToken:  "ABCDEFGHIJKLMNOP1234567890",
		RefreshToken: "ABCDEFGHIJKLMNOP",
		IDToken:      "0123456789ABCDEF",
		Expiry:       expiry,
	}

	err := SaveToFile("/tmp/skpr/oauth.yml", tokens)
	assert.Nil(t, err)

	tokens, err = LoadFromFile("/tmp/skpr/oauth.yml")
	assert.Nil(t, err)

	assert.Equal(t, "ABCDEFGHIJKLMNOP1234567890", tokens.AccessToken, "access_token was set")
	assert.Equal(t, "ABCDEFGHIJKLMNOP", tokens.RefreshToken, "refresh_token was set")
	assert.Equal(t, "0123456789ABCDEF", tokens.IDToken, "id_token was set")
	assert.Equal(t, expiry, tokens.Expiry, "expiry was set")
}

func TestHasExpired(t *testing.T) {
	expiry := time.Now().Add(time.Duration(-300 * time.Second)).Truncate(time.Duration(time.Second))
	tokens := Tokens{
		AccessToken:  "ABCDEFGHIJKLMNOP1234567890",
		RefreshToken: "ABCDEFGHIJKLMNOP",
		IDToken:      "0123456789ABCDEF",
		Expiry:       expiry,
	}

	assert.True(t, tokens.HasExpired())
}
