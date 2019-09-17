package oauth

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestTokensCache(t *testing.T) {

	expiry := time.Now().UTC().Add(300 * time.Second).Truncate(time.Second)

	tokens := Tokens{
		AccessToken:  "ABCDEFGHIJKLMNOP1234567890",
		RefreshToken: "ABCDEFGHIJKLMNOP",
		IDToken:      "0123456789ABCDEF",
		Expiry:       expiry,
	}

	tokensCache := NewFileCache("/tmp/skpr/oauth.yml")
	err := tokensCache.Put(tokens)
	assert.Nil(t, err)

	tokens, err = tokensCache.Get()
	assert.Nil(t, err)

	assert.Equal(t, "ABCDEFGHIJKLMNOP1234567890", tokens.AccessToken, "access_token was set")
	assert.Equal(t, "ABCDEFGHIJKLMNOP", tokens.RefreshToken, "refresh_token was set")
	assert.Equal(t, "0123456789ABCDEF", tokens.IDToken, "id_token was set")
	assert.Equal(t, expiry, tokens.Expiry, "expiry was set")
}

func TestHasExpired(t *testing.T) {
	expiry := time.Now().UTC().Add(-300 * time.Second).Truncate(time.Second)
	tokens := Tokens{
		AccessToken:  "ABCDEFGHIJKLMNOP1234567890",
		RefreshToken: "ABCDEFGHIJKLMNOP",
		IDToken:      "0123456789ABCDEF",
		Expiry:       expiry,
	}

	assert.True(t, tokens.HasExpired())
}
