package config

import (
	"strings"

	"github.com/slhmy/identra/internal/bootstrap"
)

func getStringSlice(key string) []string {
	values := bootstrap.Config().GetStringSlice(key)
	if len(values) != 1 {
		return values
	}

	parts := strings.Split(values[0], ",")
	if len(parts) == 1 {
		return values
	}

	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
