package identra

import (
	"context"

	identra_v1_pb "github.com/poly-workshop/identra/gen/go/identra/v1"
	"github.com/poly-workshop/identra/internal/domain"
	"github.com/poly-workshop/identra/internal/infrastructure/cache"
	"github.com/poly-workshop/identra/internal/infrastructure/mail"
	"github.com/poly-workshop/identra/internal/infrastructure/oauth"
	"github.com/poly-workshop/identra/internal/infrastructure/security"
	"golang.org/x/oauth2"
)

// Service implements identra.v1.IdentraService.
type Service struct {
	identra_v1_pb.UnimplementedIdentraServiceServer

	emailCodeStore           cache.EmailCodeStore
	oauthStateStore          oauth.StateStore
	userStore                domain.UserStore
	externalIdentityStore    domain.ExternalIdentityStore
	userStoreCleanup         func(context.Context) error
	keyManager               *security.KeyManager
	tokenCfg                 security.TokenConfig
	githubOAuthConfig        *oauth2.Config
	oauthFetchEmailIfMissing bool
	mailer                   mail.Sender

	// loginRateLimiter counts failed login attempts per email address and
	// blocks further attempts after the configured threshold.
	loginRateLimiter cache.RateLimiter
	// sendCodeRateLimiter limits how many email verification codes can be sent
	// to a single address within the configured window.
	sendCodeRateLimiter cache.RateLimiter
	// refreshTokenRevocations blocks reuse of refresh tokens after logout,
	// explicit revocation, or successful refresh-token rotation.
	refreshTokenRevocations cache.RefreshTokenRevocationStore
}

func (s *Service) Close(ctx context.Context) error {
	if s.userStoreCleanup != nil {
		return s.userStoreCleanup(ctx)
	}
	return nil
}
