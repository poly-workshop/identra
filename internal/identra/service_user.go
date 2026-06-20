package identra

import (
	"context"
	"log/slog"
	"time"
)

func (s *Service) recordLogin(ctx context.Context, usr *UserModel) {
	now := time.Now()
	usr.LastLoginAt = &now
	if err := s.userStore.Update(ctx, usr); err != nil {
		slog.WarnContext(ctx, "failed to record last login", "error", err, "user_id", usr.ID)
	}
}
