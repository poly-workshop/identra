package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/poly-workshop/identra/internal/infrastructure/bootstrap"
	"github.com/poly-workshop/identra/internal/infrastructure/cache/redis"
	"github.com/poly-workshop/identra/internal/infrastructure/notification/smtp"
	identra_v1_pb "github.com/poly-workshop/identra/gen/go/identra/v1"
	"github.com/poly-workshop/identra/internal/application/identra"
	"github.com/poly-workshop/identra/internal/infrastructure/configs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func init() {
	bootstrap.Init("grpc")
}

// InterceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(
		func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
			l.Log(ctx, slog.Level(lvl), msg, fields...)
		},
	)
}

func main() {
	ctx := context.Background()
	cfg := configs.LoadGRPC()

	// Initialize services
	authService, err := identra.NewService(ctx,
		toIdentraConfig(cfg.Auth, cfg.Redis, cfg.SmtpMailer, cfg.Persistence))
	if err != nil {
		log.Fatalf("failed to create identra service: %v", err)
	}
	defer func() {
		if err := authService.Close(context.Background()); err != nil {
			slog.Warn("failed to cleanup service", "error", err)
		}
	}()

	// Setup gRPC server with auth interceptor
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			bootstrap.BuildRequestIDInterceptor(),
			logging.UnaryServerInterceptor(InterceptorLogger(slog.Default())),
		),
	)
	identra_v1_pb.RegisterIdentraServiceServer(grpcServer, authService)
	reflection.Register(grpcServer)

	// Start gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		log.Fatalf("failed to listen on gRPC port: %v", err)
	}

	slog.Info("gRPC server started", "port", cfg.GRPCPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve gRPC: %v", err)
	}
}

func toIdentraConfig(
	authCfg configs.AuthConfig,
	redisCfg redis.Config,
	mailerCfg smtp.Config,
	presistenceCfg configs.PersistenceConfig,
) identra.Config {
	return identra.Config{
		RSAPrivateKey:                  authCfg.RSAPrivateKey,
		GithubClientID:                 authCfg.OAuth.GithubClientID,
		GithubClientSecret:             authCfg.OAuth.GithubClientSecret,
		OAuthFetchEmailIfMissing:       authCfg.OAuth.FetchEmailIfMissing,
		OAuthStateExpirationDuration:   authCfg.OAuth.StateExpirationDuration,
		AccessTokenExpirationDuration:  authCfg.Token.AccessTokenExpiration,
		RefreshTokenExpirationDuration: authCfg.Token.RefreshTokenExpiration,
		TokenIssuer:                    authCfg.Token.Issuer,
		SmtpMailer:                     mailerCfg,
		PresistenceType:                presistenceCfg.Type,
		GORMClient:                     presistenceCfg.GORM,
		MongoClient:                    presistenceCfg.Mongo,
		RedisClient:                    &redisCfg,
	}
}
