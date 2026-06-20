package identra

import (
	"context"
	"strings"

	"google.golang.org/grpc/metadata"
)

func rateLimitKeys(ctx context.Context, scope, email string) []string {
	keys := []string{emailRateLimitKey(scope, email)}
	if client := clientRateLimitIdentity(ctx); client != "" {
		keys = append(keys, scope+":client:"+client)
	}
	return keys
}

func emailRateLimitKey(scope, email string) string {
	return scope + ":email:" + strings.ToLower(strings.TrimSpace(email))
}

func clientRateLimitIdentity(ctx context.Context) string {
	for _, key := range []string{"x-forwarded-for", "x-real-ip", "x-client-id"} {
		for _, value := range metadata.ValueFromIncomingContext(ctx, key) {
			if identity := firstHeaderValue(value); identity != "" {
				return identity
			}
		}
	}
	return ""
}

func firstHeaderValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if idx := strings.IndexByte(value, ','); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func rateLimitAllowed(ctx context.Context, limiter RateLimiter, keys []string) (bool, error) {
	for _, key := range keys {
		allowed, err := limiter.IsAllowed(ctx, key)
		if err != nil {
			return false, err
		}
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}

func recordRateLimit(ctx context.Context, limiter RateLimiter, keys []string) error {
	for _, key := range keys {
		if err := limiter.Record(ctx, key); err != nil {
			return err
		}
	}
	return nil
}
