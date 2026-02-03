// Package redis provides a factory for creating Redis connections.
package redis

import (
	"github.com/redis/go-redis/v9"
)

// Config holds the configuration for Redis connections.
type Config struct {
	Urls     []string
	Password string
}

// NewRDB creates a new Redis client with the provided configuration.
//
// The client automatically detects the mode based on the number of URLs:
//   - Single URL: Creates a standard Redis client
//   - Multiple URLs: Creates a Redis cluster client
func NewRDB(cfg Config) redis.UniversalClient {
	if len(cfg.Urls) == 0 {
		panic("redisclient: no redis hosts configured")
	}
	if len(cfg.Urls) == 1 {
		return redis.NewClient(&redis.Options{
			Addr:     cfg.Urls[0],
			Password: cfg.Password,
		})
	}
	return redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:    cfg.Urls,
		Password: cfg.Password,
	})
}
