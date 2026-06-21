package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/slhmy/identra/internal/config"
	"github.com/slhmy/identra/internal/identra"
	"github.com/slhmy/identra/internal/store"
	"github.com/slhmy/identra/internal/store/gorm"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func buildStores(ctx context.Context, cfg config.PersistenceConfig) (identra.UserStore, identra.ExternalIdentityStore, func(context.Context) error, error) {
	repoType := strings.ToLower(strings.TrimSpace(cfg.Type))
	switch repoType {
	case "mongo", "mongodb":
		return buildMongoStores(ctx, cfg)
	case "", "gorm", "postgres", "mysql", "sqlite":
		return buildGormStores(cfg)
	default:
		return nil, nil, nil, fmt.Errorf("unsupported user repository type: %s", cfg.Type)
	}
}

func buildMongoStores(ctx context.Context, cfg config.PersistenceConfig) (identra.UserStore, identra.ExternalIdentityStore, func(context.Context) error, error) {
	mongoCfg := cfg.Mongo
	client, err := mongo.Connect(options.Client().ApplyURI(mongoCfg.URI))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to connect to mongo: %w", err)
	}

	userStore, repoErr := store.NewMongoUserStore(ctx, client, mongoCfg.Database, "users")
	if repoErr != nil {
		_ = client.Disconnect(ctx)
		return nil, nil, nil, repoErr
	}

	extStore, extErr := store.NewMongoExternalIdentityStore(ctx, client, mongoCfg.Database, "external_identities")
	if extErr != nil {
		_ = client.Disconnect(ctx)
		return nil, nil, nil, extErr
	}

	cleanup := func(cleanupCtx context.Context) error {
		return client.Disconnect(cleanupCtx)
	}
	return userStore, extStore, cleanup, nil
}

func buildGormStores(cfg config.PersistenceConfig) (identra.UserStore, identra.ExternalIdentityStore, func(context.Context) error, error) {
	db, err := gorm.NewDB(*cfg.GORM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize gorm database: %w", err)
	}
	if err := store.AutoMigrateGorm(db); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to migrate database: %w", err)
	}
	userStore := store.NewGormUserStore(db)
	extStore := store.NewGormExternalIdentityStore(db)
	return userStore, extStore, func(context.Context) error { return nil }, nil
}
