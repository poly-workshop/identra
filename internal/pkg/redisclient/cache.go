package redisclient

import (
	"context"
	"log/slog"
	"time"

	"github.com/go-redis/cache/v9"
	"github.com/redis/go-redis/v9"
)

// Cache wraps the go-redis cache with pub/sub support for distributed invalidation.
type Cache struct {
	*cache.Cache
	rdb                 redis.UniversalClient
	refreshEventChannel string
}

// CacheConfig holds configuration for creating a new cache instance.
type CacheConfig struct {
	// Redis client to use for the cache. Required.
	Redis redis.UniversalClient
	// RefreshEventChannel is the name of the pub/sub channel for cache invalidation events.
	// Optional. Defaults to "cacheRefreshEventChannel".
	RefreshEventChannel string
	// LocalCacheSize is the maximum number of entries in the local cache.
	// Optional. Defaults to 1000.
	LocalCacheSize int
	// LocalCacheTTL is the time-to-live for entries in the local cache.
	// Optional. Defaults to 1 minute.
	LocalCacheTTL time.Duration
}

// NewCache creates a new cache instance with the provided configuration.
func NewCache(cfg CacheConfig) *Cache {
	if cfg.Redis == nil {
		panic("redisclient: Redis client is required for cache")
	}

	// Set defaults
	refreshEventChannel := cfg.RefreshEventChannel
	if refreshEventChannel == "" {
		refreshEventChannel = "cacheRefreshEventChannel"
	}
	localCacheSize := cfg.LocalCacheSize
	if localCacheSize == 0 {
		localCacheSize = 1000
	}
	localCacheTTL := cfg.LocalCacheTTL
	if localCacheTTL == 0 {
		localCacheTTL = time.Minute
	}

	cacheClient := cache.New(&cache.Options{
		Redis:      cfg.Redis,
		LocalCache: cache.NewTinyLFU(localCacheSize, localCacheTTL),
	})
	cacheInstance := &Cache{
		Cache:               cacheClient,
		rdb:                 cfg.Redis,
		refreshEventChannel: refreshEventChannel,
	}

	// Initialize pub/sub for cache refresh events.
	// The Set operation is used to ensure the channel key exists in Redis
	// before subscribing, which helps with initial connection validation.
	ctx := context.Background()
	_, err := cfg.Redis.Set(ctx, refreshEventChannel, refreshEventChannel, 0).Result()
	if err != nil {
		panic(err)
	}

	// Note: This goroutine runs for the lifetime of the application.
	// For long-running services, this is the expected behavior.
	go func() {
		pubsub := cfg.Redis.Subscribe(ctx, refreshEventChannel)
		defer func() {
			err := pubsub.Close()
			if err != nil {
				slog.Error("Error closing pubsub", "error", err)
			}
		}()
		slog.Info(
			"Subscribed to cache refresh event channel", "channel", refreshEventChannel)
		ch := pubsub.Channel()
		for {
			select {
			case msg := <-ch:
				slog.Info("Cache refresh event received", "key", msg.Payload)
				cacheInstance.DeleteFromLocalCache(msg.Payload)
			case <-ctx.Done():
				return
			}
		}
	}()

	return cacheInstance
}

func (c *Cache) publishCacheRefreshEvent(ctx context.Context, key string) error {
	return c.rdb.Publish(ctx, c.refreshEventChannel, key).Err()
}

// Get retrieves a value from the cache.
func (c *Cache) Get(ctx context.Context, key string, value any) error {
	return c.Cache.Get(ctx, key, value)
}

// Set stores a value in the cache with the specified expiration.
func (c *Cache) Set(ctx context.Context, key string, value any, expiration time.Duration) error {
	if err := c.Cache.Set(&cache.Item{
		Ctx:   ctx,
		Key:   key,
		Value: value,
		TTL:   expiration,
	}); err != nil {
		return err
	}
	return c.publishCacheRefreshEvent(ctx, key)
}

// Delete removes a value from the cache.
func (c *Cache) Delete(ctx context.Context, key string) error {
	if err := c.Cache.Delete(ctx, key); err != nil {
		return err
	}
	return c.publishCacheRefreshEvent(ctx, key)
}
