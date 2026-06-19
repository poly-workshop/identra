package configs

import "github.com/poly-workshop/identra/internal/infrastructure/bootstrap"

type GatewayConfig struct {
	HTTPPort uint
	GRPCPort uint
}

func LoadGateway() GatewayConfig {
	return GatewayConfig{
		HTTPPort: bootstrap.Config().GetUint(HTTPPortKey),
		GRPCPort: bootstrap.Config().GetUint(GRPCPortKey),
	}
}
