package lib

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	// Cleanup: Remove temp config file after test
	defer func() {
		_ = os.Remove("jwtplus.yaml")
	}()

	// Test Case: Config file exists and loads correctly
	t.Run("Config - Valid Config File", func(t *testing.T) {
		// Create a temporary config file
		content := []byte(`debug: false
server:
  ip: 127.0.0.1
  port: 8080
origins:
  - http://localhost
db:
  location: 127.0.0.1
  port: 3306
  username: jwtengine
  password: 123456
  dbname: jwtengine`)
		err := os.WriteFile("jwtplus.yaml", content, 0644)
		assert.NoError(t, err, "Failed to create temp config file")

		// Load the config
		err = LoadConfig()
		assert.NoError(t, err, "LoadConfig() should not return an error")

		// Check if values are loaded correctly
		assert.Equal(t, "127.0.0.1", Config.GetString("server.ip"))
		assert.Equal(t, 8080, Config.GetInt("server.port"))

		// Check if all the validation rules are also pass
		verifyConfig := VerifyConfig()
		assert.NoError(t, verifyConfig, "VerifyConfig() should not return an error")
	})

	// Test Case: Config file missing, should return an error
	t.Run("Config - Missing Config File", func(t *testing.T) {
		_ = os.Remove("jwtplus.yaml") // Ensure the file is removed
		err := LoadConfig()
		assert.Error(t, err, "LoadConfig() should return an error when config file is missing")
	})

	// Test Case: Default Values Work
	t.Run("Config - Default Values", func(t *testing.T) {
		_ = os.Remove("jwtplus.yaml") // Ensure no file exists
		Config = viper.New()          // Reset viper instance

		_ = LoadConfig()

		// Check if defaults are correctly applied
		assert.Equal(t, false, Config.GetBool("debug"))
	})
}
