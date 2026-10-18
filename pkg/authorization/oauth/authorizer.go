package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	oidc_client "github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	ErrInvalidAuthorizationHeader = errors.New("invalid authorization header, must be prefixed with `Bearer`")
	ErrIntrospectionFailed        = errors.New("token introspection failed")
)

// IntrospectionVerification 通过 OAuth2 Introspection 调用来校验传入的令牌，
// 从而提供了 [authorization.Verifier] 的实现。
// 具体实现请使用 [WithIntrospection]。
type IntrospectionVerification[T any] struct {
	rs.ResourceServer
}

// WithIntrospection 创建 [authorization.Verifier] 接口的 OAuth2 Introspection 实现。
// introspection 端点本身要求客户端提供某种 [IntrospectionAuthentication] 认证方式。
// 可选的实现有 [JWTProfileIntrospectionAuthentication] 和 [ClientIDSecretIntrospectionAuthentication]。
func WithIntrospection[T authorization.Ctx](auth IntrospectionAuthentication) authorization.VerifierInitializer[T] {
	return func(ctx context.Context, zitadel *zitadel.Zitadel) (authorization.Verifier[T], error) {
		resourceServer, err := auth(ctx, zitadel.Origin())
		if err != nil {
			return nil, err
		}
		return &IntrospectionVerification[T]{
			ResourceServer: resourceServer,
		}, nil
	}
}

type IntrospectionAuthentication func(ctx context.Context, issuer string) (rs.ResourceServer, error)

// IntrospectionAuthenticationJWTProfile 允许使用 ZITADEL 提供的 key.json，
// 通过 JWT Profile 对 introspection 请求进行认证。
func IntrospectionAuthenticationJWTProfile(file *client.KeyFile) IntrospectionAuthentication {
	return func(ctx context.Context, issuer string) (rs.ResourceServer, error) {
		return rs.NewResourceServerJWTProfile(ctx, issuer, file.ClientID, file.KeyID, []byte(file.Key))
	}
}

// JWTProfileIntrospectionAuthentication 允许使用 ZITADEL 提供的 key.json，
// 通过 JWT Profile 对 introspection 请求进行认证。
// 已废弃：请改用 [IntrospectionAuthenticationJWTProfile]，它使用了正确的 [client.KeyFile] 类型。
//
//nolint:staticcheck // 为向后兼容保留该废弃签名。
func JWTProfileIntrospectionAuthentication(file *oidc_client.KeyFile) IntrospectionAuthentication {
	return func(ctx context.Context, issuer string) (rs.ResourceServer, error) {
		return rs.NewResourceServerJWTProfile(ctx, issuer, file.ClientID, file.KeyID, []byte(file.Key))
	}
}

// ClientIDSecretIntrospectionAuthentication 允许使用 Zitadel 提供的
// client_id 和 client_secret 对 introspection 请求进行认证。
//
//goland:noinspection GoUnusedExportedFunction
func ClientIDSecretIntrospectionAuthentication(clientID, clientSecret string) IntrospectionAuthentication {
	return func(ctx context.Context, issuer string) (rs.ResourceServer, error) {
		return rs.NewResourceServerClientCredentials(ctx, issuer, clientID, clientSecret)
	}
}

// DefaultAuthorization 是 [WithIntrospection[*IntrospectionContext](JWTProfileIntrospectionAuthentication)]
// 的简化版本，会从给定路径读取 key.json。
func DefaultAuthorization(path string) authorization.VerifierInitializer[*IntrospectionContext] {
	c, err := client.ConfigFromKeyFile(path)
	if err != nil {
		return func(ctx context.Context, _ *zitadel.Zitadel) (authorization.Verifier[*IntrospectionContext], error) {
			return nil, err
		}
	}
	return WithIntrospection[*IntrospectionContext](IntrospectionAuthenticationJWTProfile(c))
}

// CheckAuthorization 通过在 OAuth2 introspection 端点上校验 authorizationToken，
// 实现了 [authorization.Verifier] 接口。
// 校验成功时，它会返回 [IntrospectionVerification] 中类型为 [T] 的泛型结构体。
func (i *IntrospectionVerification[T]) CheckAuthorization(ctx context.Context, authorizationToken string) (resp T, err error) {
	accessToken, ok := strings.CutPrefix(authorizationToken, oidc.BearerToken)
	if !ok {
		return resp, ErrInvalidAuthorizationHeader
	}
	resp, err = rs.Introspect[T](ctx, i.ResourceServer, strings.TrimSpace(accessToken))
	if err != nil {
		return resp, fmt.Errorf("%w: %v", ErrIntrospectionFailed, err)
	}
	return resp, nil
}
