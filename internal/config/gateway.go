package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/slhmy/identra/internal/bootstrap"
)

type GatewayConfig struct {
	HTTPPort     uint
	GRPCEndpoint string
	CORS         CORSConfig
}

type CORSConfig struct {
	AllowedOrigins   []string
	AllowCredentials bool
}

func (c GatewayConfig) Validate() error {
	if c.HTTPPort == 0 {
		return errors.New("http port is required")
	}
	if strings.TrimSpace(c.GRPCEndpoint) == "" {
		return errors.New("grpc endpoint is required")
	}
	if err := c.CORS.Validate(); err != nil {
		return fmt.Errorf("cors config: %w", err)
	}
	return nil
}

func (c CORSConfig) Validate() error {
	if !c.AllowCredentials {
		return nil
	}
	for _, origin := range c.AllowedOrigins {
		if strings.TrimSpace(origin) == "*" {
			return errors.New("allowed origins cannot contain * when credentials are enabled")
		}
	}
	return nil
}

func LoadGateway() GatewayConfig {
	return GatewayConfig{
		HTTPPort:     bootstrap.Config().GetUint(HTTPPortKey),
		GRPCEndpoint: bootstrap.Config().GetString(GRPCEndpointKey),
		CORS: CORSConfig{
			AllowedOrigins:   getStringSlice(CORSAllowedOriginsKey),
			AllowCredentials: bootstrap.Config().GetBool(CORSAllowCredentialsKey),
		},
	}
}
