package domain

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a resource is not found.
var ErrNotFound = errors.New("resource not found")

// ErrAlreadyExists is returned when a resource with the same unique key already exists.
var ErrAlreadyExists = errors.New("resource already exists")

// UserModel represents a user entity in the system.
type UserModel struct {
	ID               string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Email            string
	HashedPassword   *string
	VerificationHash *string
	LastLoginAt      *time.Time
}

// UserStore defines the interface for user persistence operations.
type UserStore interface {
	Create(ctx context.Context, user *UserModel) error
	GetByID(ctx context.Context, id string) (*UserModel, error)
	GetByEmail(ctx context.Context, email string) (*UserModel, error)
	Update(ctx context.Context, user *UserModel) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, offset, limit int) ([]*UserModel, error)
	Count(ctx context.Context) (int64, error)
}
