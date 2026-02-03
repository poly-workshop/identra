// Package bootstrap provides application initialization and configuration management.
package bootstrap

import (
	"path"
	"strings"

	"github.com/spf13/viper"
)

const (
	defaultConfigName = "default"
)

var config *viper.Viper

// Config returns the application configuration instance.
func Config() *viper.Viper {
	return config
}

func initConfig(configPath string) {
	viper.AddConfigPath(configPath)

	viper.SetConfigName(defaultConfigName)
	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			panic(err)
		}
	}

	viper.SetConfigName(path.Join(cmdName, defaultConfigName))
	err = viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			panic(err)
		}
	}

	viper.SetConfigName(mode)
	err = viper.MergeInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			panic(err)
		}
	}

	viper.SetConfigName(path.Join(cmdName, mode))
	err = viper.MergeInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			panic(err)
		}
	}

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	config = viper.GetViper()
}
