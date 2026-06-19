package configs

import "github.com/poly-workshop/identra/internal/infrastructure/bootstrap"

type GatewayConfig struct {
	HTTPPort     uint
	GRPCEndpoint string
}

func LoadGateway() GatewayConfig {
	return GatewayConfig{
		HTTPPort:     bootstrap.Config().GetUint(HTTPPortKey),
		GRPCEndpoint: bootstrap.Config().GetString(GRPCEndpointKey),
	}
}
