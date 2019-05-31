package cognito

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSaveAndLoadFromFile(t *testing.T) {
	c, err := LoadFromFile("test_fixtures/cognito_config.yml")
	assert.Nil(t, err)
	assert.Equal(t, "LMNOPQRTSUV", c.UserPoolID, "user_pool_id was set")
	assert.Equal(t, "WXYZ0123456789", c.IdentityPoolID, "identity_pool_id was set")
	assert.Equal(t, "ABCDEFGHIJK", c.ClientID, "client_id was set")
}
