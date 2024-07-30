package auth_library

import (
	"github.com/YATAHAKI/auth-library/implementations/keycloak_redis"
	"github.com/YATAHAKI/auth-library/provider"
	"go.uber.org/fx"
)

var AuthKeycloakModule = fx.Module(
	"auth_keycloak",
	fx.Provide(
		keycloak_redis.LoadConfig,
		fx.Annotate(
			keycloak_redis.NewProvider,
			fx.As(new(provider.AuthProvider)),
		),
	),
)
