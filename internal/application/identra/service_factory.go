package identra

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/poly-workshop/identra/internal/domain"
	"github.com/poly-workshop/identra/internal/infrastructure/cache"
	"github.com/poly-workshop/identra/internal/infrastructure/cache/redis"
	"github.com/poly-workshop/identra/internal/infrastructure/mail"
	"github.com/poly-workshop/identra/internal/infrastructure/notification/smtp"
	"github.com/poly-workshop/identra/internal/infrastructure/persistence"
	"github.com/poly-workshop/identra/internal/infrastructure/persistence/gorm"
	"github.com/poly-workshop/identra/internal/infrastructure/security"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func NewService(ctx context.Context, cfg Config) (*Service, error) {
	mailerCfg := cfg.SmtpMailer
	var mailer mail.Sender

	if strings.TrimSpace(mailerCfg.Host) != "" {
		if err := validateMailerConfig(mailerCfg); err != nil {
			return nil, fmt.Errorf("invalid mailer config: %w", err)
		}

		mailer = smtp.NewMailer(mailerCfg)
	}

	km := security.GetKeyManager()
	if cfg.RSAPrivateKey != "" {
		if err := km.InitializeFromPEM(cfg.RSAPrivateKey); err != nil {
			return nil, fmt.Errorf("failed to load RSA private key: %w", err)
		}
	}
	if !km.IsInitialized() {
		if err := km.GenerateKeyPair(); err != nil {
			return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}
	}

	tokenCfg := security.TokenConfig{
		PrivateKey:             km.GetPrivateKey(),
		PublicKey:              km.GetPublicKey(),
		KeyID:                  km.GetKeyID(),
		Issuer:                 cfg.TokenIssuer,
		AccessTokenExpiration:  cfg.AccessTokenExpirationDuration,
		RefreshTokenExpiration: cfg.RefreshTokenExpirationDuration,
	}
	if tokenCfg.PrivateKey == nil || tokenCfg.PublicKey == nil {
		return nil, errors.New("token keys are not initialized")
	}

	stateTTL := cfg.OAuthStateExpirationDuration
	if stateTTL <= 0 {
		stateTTL = DefaultOAuthStateExpiration
	}

	userStore, externalIdentityStore, cleanup, storeErr := buildStores(ctx, cfg)
	if storeErr != nil {
		return nil, storeErr
	}

	githubCfg := &oauth2.Config{
		ClientID:     cfg.GithubClientID,
		ClientSecret: cfg.GithubClientSecret,
		Scopes:       []string{"read:user", "user:email"},
		Endpoint:     github.Endpoint,
	}

	rdb, storeErr := redis.NewRDB(*cfg.RedisClient)
	if storeErr != nil {
		return nil, fmt.Errorf("failed to initialize redis client: %w", storeErr)
	}

	emailStore, storeErr := cache.NewRedisEmailCodeStore(10*time.Minute, rdb)
	if storeErr != nil {
		return nil, fmt.Errorf("failed to initialize email code store: %w", storeErr)
	}

	oauthStore, storeErr := cache.NewRedisOAuthStateStore(stateTTL, rdb)
	if storeErr != nil {
		return nil, fmt.Errorf("failed to initialize oauth state store: %w", storeErr)
	}

	loginMaxAttempts := cfg.LoginMaxAttempts
	if loginMaxAttempts <= 0 {
		loginMaxAttempts = DefaultLoginMaxAttempts
	}
	loginLockoutDuration := cfg.LoginLockoutDuration
	if loginLockoutDuration <= 0 {
		loginLockoutDuration = DefaultLoginLockoutDuration
	}

	loginLimiter, loginLimiterErr := cache.NewRedisRateLimiter(
		rdb,
		"identra:rl:login:",
		loginMaxAttempts,
		loginLockoutDuration,
	)
	if loginLimiterErr != nil {
		return nil, fmt.Errorf("failed to initialize login rate limiter: %w", loginLimiterErr)
	}

	sendCodeMaxAttempts := cfg.SendCodeMaxAttempts
	if sendCodeMaxAttempts <= 0 {
		sendCodeMaxAttempts = DefaultSendCodeMaxAttempts
	}
	sendCodeWindow := cfg.SendCodeWindow
	if sendCodeWindow <= 0 {
		sendCodeWindow = DefaultSendCodeWindow
	}

	sendCodeLimiter, sendCodeLimiterErr := cache.NewRedisRateLimiter(
		rdb,
		"identra:rl:send_code:",
		sendCodeMaxAttempts,
		sendCodeWindow,
	)
	if sendCodeLimiterErr != nil {
		return nil, fmt.Errorf("failed to initialize send-code rate limiter: %w", sendCodeLimiterErr)
	}

	refreshRevocations, refreshRevocationsErr := cache.NewRedisRefreshTokenRevocationStore(rdb)
	if refreshRevocationsErr != nil {
		return nil, fmt.Errorf("failed to initialize refresh token revocation store: %w", refreshRevocationsErr)
	}

	return &Service{
		userStore:                userStore,
		externalIdentityStore:    externalIdentityStore,
		keyManager:               km,
		tokenCfg:                 tokenCfg,
		oauthStateStore:          oauthStore,
		emailCodeStore:           emailStore,
		githubOAuthConfig:        githubCfg,
		oauthFetchEmailIfMissing: cfg.OAuthFetchEmailIfMissing,
		mailer:                   mailer,
		userStoreCleanup:         cleanup,
		loginRateLimiter:         loginLimiter,
		sendCodeRateLimiter:      sendCodeLimiter,
		refreshTokenRevocations:  refreshRevocations,
	}, nil
}

// Close releases resources owned by the service.

func validateMailerConfig(cfg smtp.Config) error {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil
	}

	switch {
	case cfg.Port == 0:
		return errors.New("smtp port is required")
	case strings.TrimSpace(cfg.Username) == "":
		return errors.New("smtp username is required")
	case strings.TrimSpace(cfg.Password) == "":
		return errors.New("smtp password is required")
	case strings.TrimSpace(cfg.FromEmail) == "":
		return errors.New("smtp from email is required")
	default:
		return nil
	}
}

func buildStores(ctx context.Context, cfg Config) (domain.UserStore, domain.ExternalIdentityStore, func(context.Context) error, error) {
	repoType := strings.ToLower(strings.TrimSpace(cfg.PersistenceType))
	switch repoType {
	case "mongo", "mongodb":
		mongoCfg := cfg.MongoClient
		if strings.TrimSpace(mongoCfg.URI) == "" {
			return nil, nil, nil, fmt.Errorf("mongo uri is required when using mongo user repository")
		}
		if strings.TrimSpace(mongoCfg.Database) == "" {
			return nil, nil, nil, fmt.Errorf("mongo database is required when using mongo user repository")
		}

		client, err := mongo.Connect(options.Client().ApplyURI(mongoCfg.URI))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to connect to mongo: %w", err)
		}

		userStore, repoErr := persistence.NewMongoUserStore(ctx, client, mongoCfg.Database, "users")
		if repoErr != nil {
			_ = client.Disconnect(ctx)
			return nil, nil, nil, repoErr
		}

		extStore, extErr := persistence.NewMongoExternalIdentityStore(ctx, client, mongoCfg.Database, "external_identities")
		if extErr != nil {
			_ = client.Disconnect(ctx)
			return nil, nil, nil, extErr
		}

		cleanup := func(cleanupCtx context.Context) error {
			return client.Disconnect(cleanupCtx)
		}
		return userStore, extStore, cleanup, nil
	case "", "gorm", "postgres", "mysql", "sqlite":
		db, dbErr := gorm.NewDB(*cfg.GORMClient)
		if dbErr != nil {
			return nil, nil, nil, fmt.Errorf("failed to initialize gorm database: %w", dbErr)
		}
		if err := db.AutoMigrate(&domain.UserModel{}, &domain.ExternalIdentityModel{}); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to migrate database: %w", err)
		}
		userStore := persistence.NewGormUserStore(db)
		extStore := persistence.NewGormExternalIdentityStore(db)
		return userStore, extStore, func(context.Context) error { return nil }, nil
	default:
		return nil, nil, nil, fmt.Errorf("unsupported user repository type: %s", cfg.PersistenceType)
	}
}
