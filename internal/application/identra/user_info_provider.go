package identra

import (
	"context"
	"fmt"

	"github.com/google/go-github/v73/github"
)

type UserInfo struct {
	ID    string
	Email string
}

type UserInfoProvider interface {
	GetUserInfo(ctx context.Context, token string) (UserInfo, error)
}

func GetUserProvider(name string) (UserInfoProvider, error) {
	switch name {
	case "github":
		return &GitHubUserInfoProvider{}, nil
	default:
		return nil, fmt.Errorf("provider %s not supported", name)
	}
}

type GitHubUserInfoProvider struct{}

func (g *GitHubUserInfoProvider) GetUserInfo(ctx context.Context, token string) (UserInfo, error) {
	client := github.NewClient(nil).WithAuthToken(token)
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return UserInfo{}, err
	}
	return UserInfo{
		ID:    fmt.Sprintf("%d", user.GetID()),
		Email: user.GetEmail(),
	}, nil
}
