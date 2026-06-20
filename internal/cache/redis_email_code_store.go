package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// EmailCodeStore defines the interface for email verification code storage.
type EmailCodeStore interface {
	Set(ctx context.Context, email, code string) error
	Consume(ctx context.Context, email, code string) (bool, error)
}

// NewRedisEmailCodeStore creates a Redis-backed email code store.
func NewRedisEmailCodeStore(ttl time.Duration, rdb redis.UniversalClient) (EmailCodeStore, error) {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if rdb == nil {
		return nil, errors.New("redis client is required for email code store")
	}
	return &redisEmailCodeStore{rdb: rdb, ttl: ttl, prefix: "identra:email_code:"}, nil
}

type redisEmailCodeStore struct {
	rdb    redis.UniversalClient
	ttl    time.Duration
	prefix string
}

func (s *redisEmailCodeStore) key(email string) string {
	return s.prefix + email
}

func (s *redisEmailCodeStore) Set(ctx context.Context, email, code string) error {
	return s.rdb.Set(ctx, s.key(email), code, s.ttl).Err()
}

var consumeEmailCodeScript = redis.NewScript(`
local v = redis.call("GET", KEYS[1])
if not v then return 0 end
if v ~= ARGV[1] then return -1 end
redis.call("DEL", KEYS[1])
return 1
`)

func (s *redisEmailCodeStore) Consume(ctx context.Context, email, code string) (bool, error) {
	res, err := consumeEmailCodeScript.Run(ctx, s.rdb, []string{s.key(email)}, code).Int()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}
