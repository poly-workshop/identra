// Package bootstrap provides application initialization and configuration management.
package bootstrap

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

const (
	configName = "config"
)

var config *viper.Viper

// Config returns the application configuration instance.
func Config() *viper.Viper {
	return config
}

func initConfig(configPath string) error {
	v := viper.New()
	applyConfigDefaults(v)
	v.AddConfigPath(configPath)
	v.SetConfigName(configName)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config: %w", err)
		}
	}

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	config = v
	return nil
}
