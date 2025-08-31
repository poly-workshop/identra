package oauth

import (
	"sync"
	"time"
)

// State represents an OAuth state entry.
type State struct {
	Provider    string
	RedirectURL string
	ExpiresAt   time.Time
}

// StateStore defines the interface for OAuth state storage.
type StateStore interface {
	Add(state, provider, redirectURL string)
	Consume(state string) (State, bool)
}

type inMemoryStateStore struct {
	mu     sync.Mutex
	ttl    time.Duration
	values map[string]State
}

// NewInMemoryStateStore creates an in-memory OAuth state store.
func NewInMemoryStateStore(ttl time.Duration) StateStore {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &inMemoryStateStore{
		ttl:    ttl,
		values: make(map[string]State),
	}
}

// Add stores a new state with its provider and redirect URL.
func (s *inMemoryStateStore) Add(state, provider, redirectURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked()
	s.values[state] = State{
		Provider:    provider,
		RedirectURL: redirectURL,
		ExpiresAt:   time.Now().Add(s.ttl),
	}
}

// Consume returns the state details when valid and removes it from the store.
func (s *inMemoryStateStore) Consume(state string) (State, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked()
	value, ok := s.values[state]
	if !ok {
		return State{}, false
	}
	delete(s.values, state)

	if time.Now().After(value.ExpiresAt) {
		return State{}, false
	}

	return value, true
}

func (s *inMemoryStateStore) cleanupLocked() {
	now := time.Now()
	for key, value := range s.values {
		if now.After(value.ExpiresAt) {
			delete(s.values, key)
		}
	}
}
