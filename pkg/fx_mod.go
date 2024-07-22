package pkg

import (
	"github.com/neiasit/auth-library/pkg/implementations/keycloak_redis"
	"github.com/neiasit/auth-library/pkg/provider"
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
