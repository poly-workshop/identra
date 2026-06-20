package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	identra_v1_pb "github.com/poly-workshop/identra/gen/go/identra/v1"
	"github.com/poly-workshop/identra/internal/infrastructure/assembly"
	"github.com/poly-workshop/identra/internal/infrastructure/bootstrap"
	"github.com/poly-workshop/identra/internal/infrastructure/configs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
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

	authService, err := assembly.NewIdentraService(ctx, cfg)
	if err != nil {
		log.Fatalf("failed to create identra service: %v", err)
	}
	defer func() {
		if err := authService.Close(context.Background()); err != nil {
			slog.Warn("failed to cleanup service", "error", err)
		}
	}()

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			bootstrap.BuildRequestIDInterceptor(),
			logging.UnaryServerInterceptor(InterceptorLogger(slog.Default())),
		),
	)
	identra_v1_pb.RegisterIdentraServiceServer(grpcServer, authService)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	reflection.Register(grpcServer)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
	if err != nil {
		log.Fatalf("failed to listen on gRPC port: %v", err)
	}

	slog.Info("gRPC server started", "port", cfg.GRPCPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve gRPC: %v", err)
	}
}
