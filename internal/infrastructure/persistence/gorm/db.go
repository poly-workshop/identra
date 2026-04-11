// Package gorm provides a factory for creating GORM database connections.
package gorm

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

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
	if cfg.DbName != "" {
		ensurePostgresDatabase(cfg)
	}

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

// ensurePostgresDatabase connects to the default "postgres" database and
// creates the target database if it does not already exist.
func ensurePostgresDatabase(cfg Config) {
	adminDSN := fmt.Sprintf(
		"host=%s port=%d user=%s dbname=postgres password=%s sslmode=%s",
		cfg.Host,
		cfg.Port,
		cfg.Username,
		cfg.Password,
		cfg.SSLMode,
	)
	adminDB, err := gorm.Open(postgres.Open(adminDSN), &gorm.Config{})
	if err != nil {
		slog.Warn("could not connect to postgres to ensure database exists", "error", err)
		return
	}
	sqlDB, err := adminDB.DB()
	if err != nil {
		slog.Warn("could not get underlying sql.DB for admin connection", "error", err)
		return
	}
	defer sqlDB.Close()

	var count int64
	if err := adminDB.Raw("SELECT COUNT(*) FROM pg_database WHERE datname = ?", cfg.DbName).Scan(&count).Error; err != nil {
		slog.Warn("could not check if database exists", "database", cfg.DbName, "error", err)
		return
	}
	if count > 0 {
		return
	}

	quotedName := quotePostgresIdentifier(cfg.DbName)
	if err := adminDB.Exec(fmt.Sprintf("CREATE DATABASE %s", quotedName)).Error; err != nil {
		slog.Warn("could not create database", "database", cfg.DbName, "error", err)
		return
	}
	slog.Info("created database", "database", cfg.DbName)
}

func openMysql(cfg Config) (db *gorm.DB, err error) {
	if cfg.DbName != "" {
		ensureMysqlDatabase(cfg)
	}

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

// ensureMysqlDatabase connects to MySQL without a specific database and
// creates the target database if it does not already exist.
func ensureMysqlDatabase(cfg Config) {
	adminDSN := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
	)
	adminDB, err := gorm.Open(mysql.Open(adminDSN), &gorm.Config{})
	if err != nil {
		slog.Warn("could not connect to mysql to ensure database exists", "error", err)
		return
	}
	sqlDB, err := adminDB.DB()
	if err != nil {
		slog.Warn("could not get underlying sql.DB for admin connection", "error", err)
		return
	}
	defer sqlDB.Close()

	quotedName := quoteMysqlIdentifier(cfg.DbName)
	if err := adminDB.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", quotedName)).Error; err != nil {
		slog.Warn("could not create database", "database", cfg.DbName, "error", err)
		return
	}
	slog.Info("ensured database exists", "database", cfg.DbName)
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

// quotePostgresIdentifier quotes a PostgreSQL identifier (e.g. database name)
// by wrapping it in double quotes and escaping any embedded double quotes.
func quotePostgresIdentifier(name string) string {
	return fmt.Sprintf(`"%s"`, strings.ReplaceAll(name, `"`, `""`))
}

// quoteMysqlIdentifier quotes a MySQL identifier (e.g. database name)
// by wrapping it in backticks and escaping any embedded backticks.
func quoteMysqlIdentifier(name string) string {
	return fmt.Sprintf("`%s`", strings.ReplaceAll(name, "`", "``"))
}
