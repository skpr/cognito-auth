package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSaveAndLoadFromFile(t *testing.T) {
	config, err := LoadFromFile("test_fixtures/config.yml")
	assert.Nil(t, err)
	assert.Equal(t, "LMNOPQRTSUV", UserPoolID, "user_pool_id was set")
	assert.Equal(t, "WXYZ0123456789", IdentityPoolID, "identity_pool_id was set")
	assert.Equal(t, "ABCDEFGHIJK", ClientID, "client_id was set")
}
