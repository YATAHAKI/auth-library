// TODO: write unit tests

package provider

import (
	"context"
	"github.com/YATAHAKI/auth-library/models"
	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
)

type AuthProvider interface {
	VerifyToken(ctx context.Context, tokenString string) (*jwt.Token, error)
	TokenKeyfunc(ctx context.Context) jwt.Keyfunc
	FetchJwkSet(ctx context.Context) (jwk.Set, error)
	IsUserHaveRoles(roles []string, userRoles []string) bool
	SerializeJwkSet(key jwk.Set) (string, error)
	DeserializeJwkSet(serializedKey string) (jwk.Set, error)
	Authorize(ctx context.Context, path string, tokenString string) (models.UserDetails, error)
	AddEndpointSecurity(endpoint string, roles ...string)
}

const (
	JwkKeySet      = "jwk-set"
	UserDetailsKey = "userDetails"
)
