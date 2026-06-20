// Package bootstrap provides gRPC server interceptors for logging and request
// ID tracking with context propagation.
package bootstrap

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// BuildRequestIDInterceptor creates a gRPC interceptor that adds a unique request ID to the context.
func BuildRequestIDInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		var requestID string

		// Check if request ID is already present in incoming metadata
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if ids := md.Get("x-request-id"); len(ids) > 0 && ids[0] != "" {
				requestID = ids[0]
			}
		}

		// Generate new request ID if not found in metadata
		if requestID == "" {
			requestID = uuid.New().String()
		}

		ctx = WithLogAttrs(ctx, slog.String("request_id", requestID))

		// Call the handler
		resp, err := handler(ctx, req)

		// Set the request ID in response metadata
		if err := grpc.SetHeader(ctx, metadata.Pairs("x-request-id", requestID)); err != nil {
			slog.Error("failed to set response header", "error", err)
		}

		return resp, err
	}
}
