package identra

import (
	"context"
	"testing"
)

type fakeGitHubUserInfoProvider struct {
	userInfo UserInfo
	err      error
}

func (f *fakeGitHubUserInfoProvider) GetUserInfo(ctx context.Context, token string) (UserInfo, error) {
	if f.err != nil {
		return UserInfo{}, f.err
	}
	return f.userInfo, nil
}

func TestUserInfoIncludesUsernameAndAvatar(t *testing.T) {
	provider := &fakeGitHubUserInfoProvider{
		userInfo: UserInfo{
			ID:        "123",
			Email:     "user@example.com",
			Username:  "testuser",
			AvatarURL: "https://avatars.githubusercontent.com/u/123",
		},
	}

	info, err := provider.GetUserInfo(context.Background(), "fake-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if info.ID != "123" {
		t.Errorf("expected ID to be '123', got %q", info.ID)
	}
	if info.Email != "user@example.com" {
		t.Errorf("expected Email to be 'user@example.com', got %q", info.Email)
	}
	if info.Username != "testuser" {
		t.Errorf("expected Username to be 'testuser', got %q", info.Username)
	}
	if info.AvatarURL != "https://avatars.githubusercontent.com/u/123" {
		t.Errorf("expected AvatarURL to be 'https://avatars.githubusercontent.com/u/123', got %q", info.AvatarURL)
	}
}

func TestUserInfoWithEmptyUsernameAndAvatar(t *testing.T) {
	provider := &fakeGitHubUserInfoProvider{
		userInfo: UserInfo{
			ID:        "456",
			Email:     "another@example.com",
			Username:  "",
			AvatarURL: "",
		},
	}

	info, err := provider.GetUserInfo(context.Background(), "fake-token")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if info.ID != "456" {
		t.Errorf("expected ID to be '456', got %q", info.ID)
	}
	if info.Email != "another@example.com" {
		t.Errorf("expected Email to be 'another@example.com', got %q", info.Email)
	}
	if info.Username != "" {
		t.Errorf("expected Username to be empty, got %q", info.Username)
	}
	if info.AvatarURL != "" {
		t.Errorf("expected AvatarURL to be empty, got %q", info.AvatarURL)
	}
}
