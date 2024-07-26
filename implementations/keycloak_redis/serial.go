package keycloak_redis

import (
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwk"
	"log/slog"
)

// SerializeJwkSet сериализует jwk.Set в строку JSON.
func (p *Provider) SerializeJwkSet(key jwk.Set) (string, error) {
	// Сериализуем ключи JWK в строку JSON.
	serializedKey, err := json.Marshal(key)
	if err != nil {
		p.logger.Error("Failed to serialize JWK set", slog.String("err", err.Error()))
		return "", err
	}
	return string(serializedKey), nil
}

// DeserializeJwkSet десериализует строку JSON в jwk.Set.
func (p *Provider) DeserializeJwkSet(serializedKey string) (jwk.Set, error) {
	keySet, err := jwk.Parse([]byte(serializedKey))
	if err != nil {
		p.logger.Error("Failed to deserialize JWK set", slog.String("err", err.Error()))
		return nil, err
	}
	return keySet, nil
}
