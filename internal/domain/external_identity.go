package domain

import (
	"context"
	"time"
)

// ExternalIdentityModel represents an OAuth provider identity linked to a user.
// Each row represents the binding (provider, provider_user_id) -> user_id.
type ExternalIdentityModel struct {
	ID             string
	UserID         string
	Provider       string
	ProviderUserID string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ExternalIdentityStore defines the interface for external identity persistence operations.
type ExternalIdentityStore interface {
	// Create persists a new external identity. Returns ErrAlreadyExists if the
	// (provider, provider_user_id) pair is already linked to a user.
	Create(ctx context.Context, identity *ExternalIdentityModel) error
	// GetByProviderID looks up a single external identity by (provider, provider_user_id).
	// Returns ErrNotFound if no match exists.
	GetByProviderID(ctx context.Context, provider, providerUserID string) (*ExternalIdentityModel, error)
	// GetByUserID returns all external identities linked to the given user.
	GetByUserID(ctx context.Context, userID string) ([]*ExternalIdentityModel, error)
}
