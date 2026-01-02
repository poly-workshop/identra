package identra

import (
	"context"
	"testing"
)

type fakeUserInfoProvider struct{}

func (f fakeUserInfoProvider) GetUserInfo(ctx context.Context, token string) (UserInfo, error) {
	return UserInfo{}, nil
}

type fakeEmailProvider struct {
	email       string
	calledCount int
}

func (f *fakeEmailProvider) GetUserInfo(ctx context.Context, token string) (UserInfo, error) {
	return UserInfo{}, nil
}

func (f *fakeEmailProvider) GetEmail(ctx context.Context, token string) (string, error) {
	f.calledCount++
	return f.email, nil
}

func TestMaybeFillOAuthEmail_DoesNothingWhenDisabled(t *testing.T) {
	s := &Service{oauthFetchEmailIfMissing: false}
	p := &fakeEmailProvider{email: "a@example.com"}
	info := &UserInfo{ID: "1", Email: ""}

	s.maybeFillOAuthEmail(context.Background(), p, "token", info)
	if info.Email != "" {
		t.Fatalf("expected email to remain empty, got %q", info.Email)
	}
	if p.calledCount != 0 {
		t.Fatalf("expected GetEmail not to be called, got %d", p.calledCount)
	}
}

func TestMaybeFillOAuthEmail_FillsWhenEnabledAndMissing(t *testing.T) {
	s := &Service{oauthFetchEmailIfMissing: true}
	p := &fakeEmailProvider{email: "a@example.com"}
	info := &UserInfo{ID: "1", Email: ""}

	s.maybeFillOAuthEmail(context.Background(), p, "token", info)
	if info.Email != "a@example.com" {
		t.Fatalf("expected email to be filled, got %q", info.Email)
	}
	if p.calledCount != 1 {
		t.Fatalf("expected GetEmail called once, got %d", p.calledCount)
	}
}

func TestMaybeFillOAuthEmail_DoesNothingIfAlreadyPresent(t *testing.T) {
	s := &Service{oauthFetchEmailIfMissing: true}
	p := &fakeEmailProvider{email: "b@example.com"}
	info := &UserInfo{ID: "1", Email: "a@example.com"}

	s.maybeFillOAuthEmail(context.Background(), p, "token", info)
	if info.Email != "a@example.com" {
		t.Fatalf("expected email unchanged, got %q", info.Email)
	}
	if p.calledCount != 0 {
		t.Fatalf("expected GetEmail not to be called, got %d", p.calledCount)
	}
}

func TestMaybeFillOAuthEmail_DoesNothingIfProviderDoesNotSupportEmail(t *testing.T) {
	s := &Service{oauthFetchEmailIfMissing: true}
	p := fakeUserInfoProvider{}
	info := &UserInfo{ID: "1", Email: ""}

	s.maybeFillOAuthEmail(context.Background(), p, "token", info)
	if info.Email != "" {
		t.Fatalf("expected email to remain empty, got %q", info.Email)
	}
}
