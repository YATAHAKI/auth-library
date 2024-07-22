package keycloak_redis

import (
	"github.com/ilyakaznacheev/cleanenv"
	"time"
)

type Config struct {
	PublicJwkUri      string        `env:"PUBLIC_JWK_URI" json:"publicJwkUri" validate:"required"`
	RefreshJwkTimeout time.Duration `env:"REFRESH_JWK_TIMEOUT" json:"refreshJwkTimeout" env-default:"3h"`
	ClientId          string        `env:"CLIENT_ID" json:"clientId" validate:"required"`
}

func LoadConfig() (*Config, error) {
	var cfg struct {
		Config Config `json:"auth" env-prefix:"AUTH_"`
	}
	err := cleanenv.ReadConfig("config.json", &cfg)
	if err != nil {
		err := cleanenv.ReadEnv(&cfg)
		if err != nil {
			return nil, err
		}
	}
	return &cfg.Config, nil
}
