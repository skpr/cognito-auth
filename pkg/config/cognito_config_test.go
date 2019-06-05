package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoad(t *testing.T) {
	c, err := Load("test_fixtures/cognito_config.yml")
	assert.Nil(t, err)
	assert.Equal(t, "LMNOPQRTSUV", c.IdentityProviderID, "identity_provider_id was set")
	assert.Equal(t, "WXYZ0123456789", c.IdentityPoolID, "identity_pool_id was set")
	assert.Equal(t, "ABCDEFGHIJK", c.ClientID, "client_id was set")
	assert.Equal(t, "ASDFGHKL", c.ClientSecret, "client_secret was set")
	assert.Equal(t, "https://console.awscreds.amazon.com/cloudwatch", c.ConsoleDestination, "console_destination was set")
	assert.Equal(t, "example.com", c.ConsoleIssuer, "console_issuer was set")
}
