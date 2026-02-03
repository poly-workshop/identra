package configs

import (
	"time"

	"github.com/poly-workshop/identra/internal/pkg/app"
	"github.com/poly-workshop/identra/internal/pkg/gormclient"
	"github.com/poly-workshop/identra/internal/pkg/mongoclient"
	"github.com/poly-workshop/identra/internal/pkg/redisclient"
	"github.com/poly-workshop/identra/internal/pkg/smtpmailer"
)

type GRPCConfig struct {
	GRPCPort    uint
	Redis       redisclient.Config
	SmtpMailer  smtpmailer.Config
	Persistence PersistenceConfig
	Auth        AuthConfig
}

type AuthConfig struct {
	RSAPrivateKey string
	OAuth         OAuthConfig
	Token         TokenConfig
}

type OAuthConfig struct {
	StateExpirationDuration time.Duration
	GithubClientID          string
	GithubClientSecret      string
	FetchEmailIfMissing     bool
}

type TokenConfig struct {
	Issuer                 string
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
}

type PersistenceConfig struct {
	Type  string
	GORM  *gormclient.Config
	Mongo *mongoclient.Config
}

const (
	DefaultOAuthStateExpiration   = 10 * time.Minute
	DefaultAccessTokenExpiration  = 15 * time.Minute
	DefaultRefreshTokenExpiration = 7 * 24 * time.Hour
	DefaultTokenIssuer            = "identra"
)

func LoadGRPC() GRPCConfig {
	cfg := GRPCConfig{
		GRPCPort: app.Config().GetUint(GRPCPortKey),
		SmtpMailer: smtpmailer.Config{
			Host:      app.Config().GetString(SmtpMailerHostKey),
			Port:      app.Config().GetInt(SmtpMailerPortKey),
			Username:  app.Config().GetString(SmtpMailerUsernameKey),
			Password:  app.Config().GetString(SmtpMailerPasswordKey),
			FromEmail: app.Config().GetString(SmtpMailerFromEmailKey),
			FromName:  app.Config().GetString(SmtpMailerFromNameKey),
		},
		Persistence: PersistenceConfig{
			Type: app.Config().GetString(PersistenceTypeKey),
			GORM: &gormclient.Config{
				Driver:   app.Config().GetString(PersistenceGORMDriverKey),
				Host:     app.Config().GetString(PersistenceGORMHostKey),
				Port:     app.Config().GetInt(PersistenceGORMPortKey),
				Username: app.Config().GetString(PersistenceGORMUsernameKey),
				Password: app.Config().GetString(PersistenceGORMPasswordKey),
				DbName:   app.Config().GetString(PersistenceGORMNameKey),
				SSLMode:  app.Config().GetString(PersistenceGORMSSLModeKey),
			},
			Mongo: &mongoclient.Config{
				URI:      app.Config().GetString(PersistenceMongoURIKey),
				Database: app.Config().GetString(PersistenceMongoDatabaseKey),
			},
		},
		Redis: redisclient.Config{
			Urls:     app.Config().GetStringSlice(RedisUrlsKey),
			Password: app.Config().GetString(RedisPasswordKey),
		},
		Auth: AuthConfig{
			RSAPrivateKey: app.Config().GetString(AuthRSAPrivateKeyKey),
			OAuth: OAuthConfig{
				StateExpirationDuration: app.Config().GetDuration(AuthOAuthStateExpirationKey),
				GithubClientID:          app.Config().GetString(AuthGithubClientIDKey),
				GithubClientSecret:      app.Config().GetString(AuthGithubClientSecretKey),
				FetchEmailIfMissing:     app.Config().GetBool(AuthOAuthFetchEmailIfMissingKey),
			},
			Token: TokenConfig{
				Issuer:                 app.Config().GetString(AuthTokenIssuerKey),
				AccessTokenExpiration:  app.Config().GetDuration(AuthAccessTokenExpirationKey),
				RefreshTokenExpiration: app.Config().GetDuration(AuthRefreshTokenExpirationKey),
			},
		},
	}

	if cfg.Auth.OAuth.StateExpirationDuration == 0 {
		cfg.Auth.OAuth.StateExpirationDuration = DefaultOAuthStateExpiration
	}
	if cfg.Auth.Token.AccessTokenExpiration == 0 {
		cfg.Auth.Token.AccessTokenExpiration = DefaultAccessTokenExpiration
	}
	if cfg.Auth.Token.RefreshTokenExpiration == 0 {
		cfg.Auth.Token.RefreshTokenExpiration = DefaultRefreshTokenExpiration
	}
	if cfg.Auth.Token.Issuer == "" {
		cfg.Auth.Token.Issuer = DefaultTokenIssuer
	}
	if cfg.Persistence.Type == "" {
		cfg.Persistence.Type = "gorm"
	}

	return cfg
}
