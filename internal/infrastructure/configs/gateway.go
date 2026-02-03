package configs

import "github.com/poly-workshop/identra/internal/infrastructure/bootstrap"

type GatewayConfig struct {
	HTTPPort uint
}

func LoadGateway() GatewayConfig {
	return GatewayConfig{
		HTTPPort: bootstrap.Config().GetUint(HTTPPortKey),
	}
}
