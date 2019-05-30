package cognito_config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSaveAndLoadFromFile(t *testing.T) {
	config, err := LoadFromFile("test_fixtures/cognito_config.yml")
	assert.Nil(t, err)
	assert.Equal(t, "LMNOPQRTSUV", config.UserPoolID, "user_pool_id was set")
	assert.Equal(t, "WXYZ0123456789", config.IdentityPoolID, "identity_pool_id was set")
	assert.Equal(t, "ABCDEFGHIJK", config.ClientID, "client_id was set")
}
