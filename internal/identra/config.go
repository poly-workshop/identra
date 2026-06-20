package identra

import "time"

const (
	DefaultOAuthStateExpiration   = 10 * time.Minute
	DefaultAccessTokenExpiration  = 15 * time.Minute   // Short-lived access token
	DefaultRefreshTokenExpiration = 7 * 24 * time.Hour // 7 days refresh token
	DefaultTokenIssuer            = "identra"

	// DefaultLoginMaxAttempts is the default maximum number of failed login
	// attempts before a temporary lockout is applied.
	DefaultLoginMaxAttempts = 5
	// DefaultLoginLockoutDuration is the default window over which failed login
	// attempts are counted.
	DefaultLoginLockoutDuration = 15 * time.Minute

	// DefaultSendCodeMaxAttempts is the default maximum number of email
	// verification codes that can be sent per address within DefaultSendCodeWindow.
	DefaultSendCodeMaxAttempts = 5
	// DefaultSendCodeWindow is the default rate-limit window for sending email
	// verification codes.
	DefaultSendCodeWindow = 1 * time.Hour
)
