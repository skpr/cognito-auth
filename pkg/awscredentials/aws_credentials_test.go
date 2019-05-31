// +build unit

package awscredentials

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestSaveAndLoadFromFile(t *testing.T) {

	expiry := time.Now().Add(time.Duration(4000 * time.Second)).Truncate(time.Duration(time.Second))

	credentials := AwsCredentials{
		AccessKey:       "ABCDEFGHIJKLMNOP",
		SecretAccessKey: "ABCDEFGHIJKLMNOP1234567890",
		SessionToken:    "1234567890ABCDEFGHIJKLMNOPQRSTU:VWXYZ|}{)(*&^%$#@!",
		Expiry:          expiry,
	}
	err := SaveToFile("/tmp/skpr/awscredentials.yml", credentials)
	assert.Nil(t, err)

	credentials, err = LoadFromFile("/tmp/skpr/awscredentials.yml")
	assert.Nil(t, err)
	assert.Equal(t, "ABCDEFGHIJKLMNOP", AccessKey, "access_key was set")
	assert.Equal(t, "ABCDEFGHIJKLMNOP1234567890", SecretAccessKey, "secret_access_key was set")
	assert.Equal(t, "1234567890ABCDEFGHIJKLMNOPQRSTU:VWXYZ|}{)(*&^%$#@!", SessionToken, "session_token was set")
	assert.Equal(t, expiry, Expiry, "expiry was set")
	assert.False(t, HasExpired())

}

func TestHasExpired(t *testing.T) {
	expiry := time.Now().Add(time.Duration(-4000 * time.Second)).Truncate(time.Duration(time.Second))

	credentials := AwsCredentials{
		AccessKey:       "ABCDEFGHIJKLMNOP",
		SecretAccessKey: "ABCDEFGHIJKLMNOP1234567890",
		SessionToken:    "1234567890ABCDEFGHIJKLMNOPQRSTU:VWXYZ|}{)(*&^%$#@!",
		Expiry:          expiry,
	}

	assert.True(t, HasExpired())
}
