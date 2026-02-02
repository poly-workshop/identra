package configs

import "github.com/poly-workshop/identra/internal/pkg/app"

type GatewayConfig struct {
	HTTPPort uint
}

func LoadGateway() GatewayConfig {
	return GatewayConfig{
		HTTPPort: app.Config().GetUint(HTTPPortKey),
	}
}
