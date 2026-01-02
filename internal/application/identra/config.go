package identra

import (
	"time"

	gormclient "github.com/poly-workshop/go-webmods/gormclient"
	mongoclient "github.com/poly-workshop/go-webmods/mongoclient"
	redisclient "github.com/poly-workshop/go-webmods/redisclient"
	smtpmailer "github.com/poly-workshop/go-webmods/smtpmailer"
)

// Config holds all settings required to run the identra service.
type Config struct {
	RSAPrivateKey                  string
	GithubClientID                 string
	GithubClientSecret             string
	OAuthFetchEmailIfMissing        bool
	OAuthStateExpirationDuration   time.Duration
	AccessTokenExpirationDuration  time.Duration
	RefreshTokenExpirationDuration time.Duration
	TokenIssuer                    string
	SmtpMailer                     smtpmailer.Config
	DatabaseType                   string
	GORMClient                     *gormclient.Config
	MongoClient                    *mongoclient.Config
	RedisClient                    *redisclient.Config
	PresistenceType                string
}

const (
	DefaultOAuthStateExpiration   = 10 * time.Minute
	DefaultAccessTokenExpiration  = 15 * time.Minute   // Short-lived access token
	DefaultRefreshTokenExpiration = 7 * 24 * time.Hour // 7 days refresh token
	DefaultTokenIssuer            = "identra"
)

type MongoConfig struct {
	URI        string
	Database   string
	Collection string
}
