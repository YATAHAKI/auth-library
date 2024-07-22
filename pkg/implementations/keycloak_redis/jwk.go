package keycloak_redis

import (
	"context"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/neiasit/auth-library/pkg/provider"
)

var _ provider.AuthProvider = (*Provider)(nil)

func (p *Provider) FetchJwkSet(ctx context.Context) (jwk.Set, error) {

	result, err := p.redis.Get(ctx, provider.JwkKeySet).Result()
	if err == nil {
		p.logger.Info("Jwk get from cache")
		resultSet, err := p.DeserializeJwkSet(result)
		if err != nil {
			return nil, err
		}
		return resultSet, nil
	}

	resultSet, err := jwk.Fetch(ctx, p.config.PublicJwkUri)
	if err != nil {
		return nil, err
	}

	p.logger.Info("Jwk get from remote")
	serializedKeySet, err := p.SerializeJwkSet(resultSet)
	if err != nil {
		return nil, err
	}

	if err := p.redis.Set(ctx, provider.JwkKeySet, serializedKeySet, p.config.RefreshJwkTimeout).Err(); err != nil {
		return nil, err
	}

	return resultSet, nil

}
