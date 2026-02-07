// Package gorm provides a factory for creating GORM database connections.
package gorm

import (
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Config holds the configuration for database connections.
type Config struct {
	Driver   string
	Host     string
	Port     int
	Username string
	Password string
	DbName   string
	SSLMode  string
}

// Validate checks that the configuration is valid for the specified driver.
// For postgres and mysql drivers, username must not be empty.
func (c Config) Validate() error {
	switch c.Driver {
	case "postgres", "mysql":
		if c.Username == "" {
			return fmt.Errorf("username is required for %s driver", c.Driver)
		}
	}
	return nil
}

// NewDB creates a new GORM database connection based on the configuration.
func NewDB(cfg Config) *gorm.DB {
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	driver := cfg.Driver
	switch driver {
	case "postgres":
		db, err := openPostgres(cfg)
		if err != nil {
			panic(err)
		}
		return db
	case "mysql":
		db, err := openMysql(cfg)
		if err != nil {
			panic(err)
		}
		return db
	case "sqlite":
		db, err := openSqlite(cfg)
		if err != nil {
			panic(err)
		}
		return db
	default:
		panic(fmt.Sprintf("unsupported database driver: %s", driver))
	}
}

func openPostgres(cfg Config) (db *gorm.DB, err error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
		cfg.Host,
		cfg.Port,
		cfg.Username,
		cfg.DbName,
		cfg.Password,
		cfg.SSLMode,
	)
	db, err = gorm.Open(postgres.Open(dsn))
	if err != nil {
		return nil, err
	}
	return db, nil
}

func openMysql(cfg Config) (db *gorm.DB, err error) {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.DbName,
	)
	db, err = gorm.Open(mysql.Open(dsn))
	if err != nil {
		return nil, err
	}
	return db, nil
}

func openSqlite(cfg Config) (db *gorm.DB, err error) {
	// Ensure directory exists for SQLite database file
	dbPath := cfg.DbName
	if dir := filepath.Dir(dbPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create directory for SQLite database: %w", err)
		}
	}

	db, err = gorm.Open(sqlite.Open(dbPath))
	if err != nil {
		return nil, err
	}
	return db, nil
}
