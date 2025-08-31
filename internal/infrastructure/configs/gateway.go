package configs

import "github.com/poly-workshop/go-webmods/app"

type GatewayConfig struct {
	HTTPPort uint
}

func LoadGateway() GatewayConfig {
	return GatewayConfig{
		HTTPPort: app.Config().GetUint(HTTPPortKey),
	}
}
