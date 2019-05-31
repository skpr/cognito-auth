package aws

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestSaveAndLoadFromFile(t *testing.T) {

	expiry := time.Now().UTC().Add(time.Duration(4000 * time.Second)).Truncate(time.Duration(time.Second))

	credentials := Credentials{
		AccessKey:       "ABCDEFGHIJKLMNOP",
		SecretAccessKey: "ABCDEFGHIJKLMNOP1234567890",
		SessionToken:    "1234567890ABCDEFGHIJKLMNOPQRSTU:VWXYZ|}{)(*&^%$#@!",
		Expiry:          expiry,
	}
	err := SaveToFile("/tmp/skpr/credentials.yml", credentials)
	assert.Nil(t, err)

	credentials, err = LoadFromFile("/tmp/skpr/credentials.yml")
	assert.Nil(t, err)
	assert.Equal(t, "ABCDEFGHIJKLMNOP", credentials.AccessKey, "access_key was set")
	assert.Equal(t, "ABCDEFGHIJKLMNOP1234567890", credentials.SecretAccessKey, "secret_access_key was set")
	assert.Equal(t, "1234567890ABCDEFGHIJKLMNOPQRSTU:VWXYZ|}{)(*&^%$#@!", credentials.SessionToken, "session_token was set")
	assert.Equal(t, expiry, credentials.Expiry, "expiry was set")
	assert.False(t, credentials.HasExpired())

}

func TestHasExpired(t *testing.T) {
	expiry := time.Now().UTC().Add(time.Duration(-4000 * time.Second)).Truncate(time.Duration(time.Second))

	credentials := Credentials{
		AccessKey:       "ABCDEFGHIJKLMNOP",
		SecretAccessKey: "ABCDEFGHIJKLMNOP1234567890",
		SessionToken:    "1234567890ABCDEFGHIJKLMNOPQRSTU:VWXYZ|}{)(*&^%$#@!",
		Expiry:          expiry,
	}

	assert.True(t, credentials.HasExpired())
}
