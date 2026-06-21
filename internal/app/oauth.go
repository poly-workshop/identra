package app

import (
	"context"

	"github.com/slhmy/identra/internal/config"
	"github.com/slhmy/identra/internal/identra"
	"github.com/slhmy/identra/internal/oauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func buildGithubOAuthConfig(cfg config.OAuthConfig) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.GithubClientID,
		ClientSecret: cfg.GithubClientSecret,
		Scopes:       []string{"read:user", "user:email"},
		Endpoint:     github.Endpoint,
	}
}

type oauthStateStoreAdapter struct {
	store oauth.StateStore
}

func (a oauthStateStoreAdapter) Add(ctx context.Context, state, provider, redirectURL string) error {
	return a.store.Add(ctx, state, provider, redirectURL)
}

func (a oauthStateStoreAdapter) Consume(ctx context.Context, state string) (identra.OAuthState, bool, error) {
	data, ok, err := a.store.Consume(ctx, state)
	return identra.OAuthState{Provider: data.Provider, RedirectURL: data.RedirectURL}, ok, err
}
