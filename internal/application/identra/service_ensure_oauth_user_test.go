package identra

import (
	"context"
	"testing"

	"github.com/poly-workshop/identra/internal/domain"
)

// mockUserStore is a simple in-memory user store for testing.
type mockUserStore struct {
	users map[string]*domain.UserModel
}

func newMockUserStore() *mockUserStore {
	return &mockUserStore{
		users: make(map[string]*domain.UserModel),
	}
}

func (m *mockUserStore) Create(ctx context.Context, user *domain.UserModel) error {
	if user.ID == "" {
		user.ID = "test-user-id"
	}
	m.users[user.ID] = user
	return nil
}

func (m *mockUserStore) GetByID(ctx context.Context, id string) (*domain.UserModel, error) {
	if user, ok := m.users[id]; ok {
		return user, nil
	}
	return nil, domain.ErrNotFound
}

func (m *mockUserStore) GetByEmail(ctx context.Context, email string) (*domain.UserModel, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockUserStore) GetByGithubID(ctx context.Context, githubID string) (*domain.UserModel, error) {
	for _, user := range m.users {
		if user.GithubID != nil && *user.GithubID == githubID {
			return user, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (m *mockUserStore) Update(ctx context.Context, user *domain.UserModel) error {
	if _, ok := m.users[user.ID]; !ok {
		return domain.ErrNotFound
	}
	m.users[user.ID] = user
	return nil
}

func (m *mockUserStore) Delete(ctx context.Context, id string) error {
	if _, ok := m.users[id]; !ok {
		return domain.ErrNotFound
	}
	delete(m.users, id)
	return nil
}

func (m *mockUserStore) List(ctx context.Context, offset, limit int) ([]*domain.UserModel, error) {
	result := make([]*domain.UserModel, 0, len(m.users))
	for _, user := range m.users {
		result = append(result, user)
	}
	return result, nil
}

func (m *mockUserStore) Count(ctx context.Context) (int64, error) {
	return int64(len(m.users)), nil
}

func TestEnsureOAuthUser_WithEmail(t *testing.T) {
	store := newMockUserStore()
	svc := &Service{userStore: store}

	info := UserInfo{
		ID:    "github123",
		Email: "user@example.com",
	}

	user, err := svc.ensureOAuthUser(context.Background(), info)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if user.Email != "user@example.com" {
		t.Errorf("expected email 'user@example.com', got %q", user.Email)
	}
	if user.GithubID == nil || *user.GithubID != "github123" {
		t.Errorf("expected GithubID 'github123', got %v", user.GithubID)
	}
}

func TestEnsureOAuthUser_WithoutEmail(t *testing.T) {
	store := newMockUserStore()
	svc := &Service{userStore: store}

	info := UserInfo{
		ID:    "github456",
		Email: "",
	}

	user, err := svc.ensureOAuthUser(context.Background(), info)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if user.Email != "" {
		t.Errorf("expected empty email, got %q", user.Email)
	}
	if user.GithubID == nil || *user.GithubID != "github456" {
		t.Errorf("expected GithubID 'github456', got %v", user.GithubID)
	}
}

func TestEnsureOAuthUser_ExistingUserByGithubID(t *testing.T) {
	store := newMockUserStore()
	svc := &Service{userStore: store}

	githubID := "github789"
	existingUser := &domain.UserModel{
		ID:       "existing-user-id",
		Email:    "existing@example.com",
		GithubID: &githubID,
	}
	_ = store.Create(context.Background(), existingUser)

	info := UserInfo{
		ID:    "github789",
		Email: "different@example.com",
	}

	user, err := svc.ensureOAuthUser(context.Background(), info)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if user.ID != existingUser.ID {
		t.Errorf("expected existing user ID, got %q", user.ID)
	}
	// Email should be updated
	if user.Email != "different@example.com" {
		t.Errorf("expected email to be updated to 'different@example.com', got %q", user.Email)
	}
}

func TestEnsureOAuthUser_LinkExistingUserByEmail(t *testing.T) {
	store := newMockUserStore()
	svc := &Service{userStore: store}

	existingUser := &domain.UserModel{
		ID:    "existing-user-id",
		Email: "existing@example.com",
	}
	_ = store.Create(context.Background(), existingUser)

	info := UserInfo{
		ID:    "github999",
		Email: "existing@example.com",
	}

	user, err := svc.ensureOAuthUser(context.Background(), info)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if user.ID != existingUser.ID {
		t.Errorf("expected existing user ID, got %q", user.ID)
	}
	if user.GithubID == nil || *user.GithubID != "github999" {
		t.Errorf("expected GithubID to be linked to 'github999', got %v", user.GithubID)
	}
}
