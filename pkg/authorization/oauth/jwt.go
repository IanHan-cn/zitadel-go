package oauth

import (
	"context"
	"errors"
	"fmt"
	gohttp "net/http"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrInvalidAudience = errors.New("invalid audience")
)

// JWTVerification 通过在本地校验携带 JWT 的 Authorization 请求头，
// 提供了 [authorization.Verifier] 的实现。
type JWTVerification struct {
	verifier *op.AccessTokenVerifier
	clientID string
}

// WithJWT 创建 [authorization.Verifier] 接口的本地 JWT 校验实现。
// 这是保护高吞吐 API 时推荐的高性能方式。
//
// 该初始化函数使用 OIDC Discovery 动态查找 JWKS URI，
// 并创建一个 [rp.RemoteKeySet]，用于在内存中获取并缓存密钥。
// 它接收用于 audience 校验的 clientID，以及可选的
// [op.AccessTokenVerifierOpt]，以便支持不同的签名算法。
func WithJWT(clientID string, httpClient *gohttp.Client, options ...op.AccessTokenVerifierOpt) authorization.VerifierInitializer[*IntrospectionContext] {
	if httpClient == nil {
		httpClient = gohttp.DefaultClient
	}

	return func(ctx context.Context, zitadel *zitadel.Zitadel) (authorization.Verifier[*IntrospectionContext], error) {
		discoveryConfig, err := client.Discover(ctx, zitadel.Origin(), httpClient)
		if err != nil {
			return nil, fmt.Errorf("OIDC discovery failed: %w", err)
		}

		keySet := rp.NewRemoteKeySet(httpClient, discoveryConfig.JwksURI)

		verifier := op.NewAccessTokenVerifier(discoveryConfig.Issuer, keySet, options...)

		return &JWTVerification{
			verifier: verifier,
			clientID: clientID,
		}, nil
	}
}

// CheckAuthorization 实现了 [authorization.Verifier] 接口，
// 用于校验 "Authorization: Bearer <token>" 请求头中的访问令牌。
//
// 校验过程在本地使用已缓存的 JWKS 密钥完成，会检查令牌的
// 签名、过期时间和签发者。校验成功时，它会返回一个
// 由已校验 JWT 的声明填充而成的 [*IntrospectionContext]。
// 这提供了一种快速、离线的令牌 introspection 替代方案。
func (j *JWTVerification) CheckAuthorization(ctx context.Context, authorizationToken string) (*IntrospectionContext, error) {
	accessToken, ok := strings.CutPrefix(authorizationToken, oidc.BearerToken)
	if !ok {
		return nil, ErrInvalidAuthorizationHeader
	}
	accessToken = strings.TrimSpace(accessToken)

	claims, err := op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, accessToken, j.verifier)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if len(claims.Audience) == 0 {
		return nil, fmt.Errorf("%w: empty aud", ErrInvalidToken)
	}
	if !slices.Contains(claims.Audience, j.clientID) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAudience, j.clientID)
	}

	resp := &IntrospectionContext{
		IntrospectionResponse: oidc.IntrospectionResponse{
			Active:     true,
			Issuer:     claims.Issuer,
			Subject:    claims.Subject,
			Audience:   claims.Audience,
			Expiration: claims.Expiration,
			IssuedAt:   claims.IssuedAt,
			NotBefore:  claims.NotBefore,
			ClientID:   claims.ClientID,
			JWTID:      claims.JWTID,
			Claims:     claims.Claims,
		},
	}
	resp.SetToken(accessToken)
	return resp, nil
}

// DefaultJWTAuthorization 为推荐的高性能 JWT 校验方式
// 提供了一个简洁的初始化函数，它是 WithJWT 的便捷封装。
//
// 它接收受保护资源服务器的 clientID，以及可选的
// [op.AccessTokenVerifierOpt]，用于定制校验行为。
func DefaultJWTAuthorization(clientID string, options ...op.AccessTokenVerifierOpt) authorization.VerifierInitializer[*IntrospectionContext] {
	return WithJWT(clientID, nil, options...)
}
