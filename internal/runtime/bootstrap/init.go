package bootstrap

import (
	"log"
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
	if err := InitE(cmd); err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}
}

// InitE initializes the application with the specified command name.
func InitE(cmd string) error {
	cmdName = cmd
	workdir, err := os.Getwd()
	if err != nil {
		return err
	}
	rootWorkdir := findRootWorkdir(workdir)
	if err := initConfig(rootWorkdir); err != nil {
		return err
	}
	initLog()
	logConfig()
	slog.Info("APP initialized")
	return nil
}

// InitWithConfigPath initializes the application with a custom config path.
func InitWithConfigPath(cmd string, configPath string) {
	if err := InitWithConfigPathE(cmd, configPath); err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}
}

// InitWithConfigPathE initializes the application with a custom config path.
func InitWithConfigPathE(cmd string, configPath string) error {
	cmdName = cmd
	if err := initConfig(configPath); err != nil {
		return err
	}
	initLog()
	logConfig()
	slog.Info("APP initialized")
	return nil
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
