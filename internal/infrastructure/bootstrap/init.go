package bootstrap

import (
	"log/slog"
	"os"
	"path/filepath"
)

var (
	cmdName     string
	hostname, _ = os.Hostname()
)

// Init initializes the application with the specified command name.
func Init(cmd string) {
	cmdName = cmd
	workdir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	rootWorkdir := findRootWorkdir(workdir)
	initConfig(rootWorkdir)
	initLog()
	logConfig()
	slog.Info("APP initialized")
}

// InitWithConfigPath initializes the application with a custom config path.
func InitWithConfigPath(cmd string, configPath string) {
	cmdName = cmd
	initConfig(configPath)
	initLog()
	logConfig()
	slog.Info("APP initialized")
}

func findRootWorkdir(start string) string {
	dir := filepath.Clean(start)
	for {
		if _, err := os.Stat(filepath.Join(dir, configName+".toml")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Clean(start)
		}
		dir = parent
	}
}
