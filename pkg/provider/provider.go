// It's legacy not usable code from this repository - https://github.com/BobrePatre/ProjectTemplate/tree/main/internal/providers/web_auth_provider
// Use this template to write perfect convenient auth provider library
// TODO: redesign the authentication provider

package provider

import (
	"context"
	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/neiasit/auth-library/pkg/models"
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
