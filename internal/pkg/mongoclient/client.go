// Package mongoclient provides a factory for creating MongoDB connections.
package mongoclient

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Config holds the configuration for MongoDB connections.
type Config struct {
	URI            string
	Database       string
	ConnectTimeout time.Duration
	PingTimeout    time.Duration
}

// NewClient creates a new MongoDB client with the provided configuration.
func NewClient(cfg Config) *mongo.Client {
	// Set default timeouts if not provided
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.PingTimeout == 0 {
		cfg.PingTimeout = 5 * time.Second
	}

	// Create MongoDB client options
	clientOptions := options.Client().ApplyURI(cfg.URI)

	// Connect to MongoDB
	client, err := mongo.Connect(clientOptions)
	if err != nil {
		panic(fmt.Sprintf("failed to connect to MongoDB: %v", err))
	}

	// Ping to verify connection
	pingCtx, pingCancel := context.WithTimeout(context.Background(), cfg.PingTimeout)
	defer pingCancel()

	if err := client.Ping(pingCtx, nil); err != nil {
		panic(fmt.Sprintf("failed to ping MongoDB: %v", err))
	}

	return client
}

// NewDatabase creates a new MongoDB database connection.
func NewDatabase(cfg Config) *mongo.Database {
	client := NewClient(cfg)
	return client.Database(cfg.Database)
}
