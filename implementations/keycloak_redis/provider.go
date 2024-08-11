package keycloak_redis

import (
	"context"
	models2 "github.com/YATAHAKI/auth-library/models"
	"github.com/YATAHAKI/auth-library/provider"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/mitchellh/mapstructure"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"sync"
	"time"
)

var _ provider.AuthProvider = (*Provider)(nil)

type JwkOptions struct {
	RefreshJwkTimeout time.Duration
	JwkPublicUri      string
}

type Provider struct {
	config           *Config
	redis            *redis.Client
	validate         *validator.Validate
	endpointSecurity map[string][]string
	m                *sync.RWMutex
	logger           *slog.Logger
}

func NewProvider(
	redis *redis.Client,
	config *Config,
	validate *validator.Validate,
	logger *slog.Logger,
) *Provider {
	return &Provider{
		config:           config,
		redis:            redis,
		validate:         validate,
		m:                &sync.RWMutex{},
		endpointSecurity: make(map[string][]string),
		logger:           logger,
	}
}

func (p *Provider) Authorize(
	ctx context.Context,
	path string,
	tokenString string,
) (
	models2.UserDetails,
	error,
) {
	token, err := p.VerifyToken(ctx, tokenString)
	if err != nil {
		p.logger.Error("failed to verify token", slog.String("err", err.Error()))
		return models2.UserDetails{}, models2.InvalidTokenError
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !(ok && token.Valid) {
		p.logger.Error("failed to get claims")
		return models2.UserDetails{}, models2.InvalidTokenError
	}

	if claims["sub"] == "" || claims["sub"] == nil {
		p.logger.Error("failed to validate sub claim")
		return models2.UserDetails{}, models2.InvalidTokenError
	}

	err = p.validate.Var(claims["sub"], "uuid4")
	if err != nil {
		p.logger.Error("failed to validate sub claim", slog.String("err", err.Error()))
		return models2.UserDetails{}, err
	}

	var userRoles []string
	if resourceAccess, ok := claims["resource_access"].(map[string]interface{}); ok {
		if authClient, ok := resourceAccess[p.config.ClientId].(map[string]interface{}); ok {
			if err := mapstructure.Decode(authClient["roles"], &userRoles); err != nil {
				p.logger.Error("cannot get user roles", slog.String("err", err.Error()))
				userRoles = []string{}
			}
		}
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		userEmail = ""
	}

	userDetails := models2.UserDetails{
		Roles:      userRoles,
		UserId:     claims["sub"].(string),
		Email:      userEmail,
		Username:   claims["preferred_username"].(string),
		Name:       claims["name"].(string),
		FamilyName: claims["family_name"].(string),
	}

	neededRoles := p.endpointSecurity[path]
	if len(neededRoles) == 0 {
		neededRoles = []string{""}
	}
	if !p.IsUserHaveRoles(neededRoles, userRoles) {
		p.logger.Error("user data", slog.Any("userDetails", userDetails))
		p.logger.Error("user doesn't have needed roles", slog.Any("neededRoles", neededRoles), slog.Any("userRoles", userRoles))
		return userDetails, models2.AccessDeniedError
	}

	return userDetails, nil
}

func (p *Provider) AddEndpointSecurity(
	endpoint string,
	roles ...string,
) {
	p.m.Lock()
	defer p.m.Unlock()
	p.endpointSecurity[endpoint] = roles
}

func (p *Provider) IsEndpointProtected(endpoint string) bool {
	p.m.RLock()
	defer p.m.RUnlock()
	_, ok := p.endpointSecurity[endpoint]
	return ok
}
