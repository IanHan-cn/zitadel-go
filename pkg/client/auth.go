package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
)

type TokenSourceInitializer func(ctx context.Context, issuer string) (oauth2.TokenSource, error)

// AuthenticationJWTProfile 允许使用 OAuth2 JWT Profile 授权模式，
// 借助 ZITADEL 提供的服务用户 key.json 来获取令牌。
func AuthenticationJWTProfile(file *KeyFile, scopes ...string) TokenSourceInitializer {
	return func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
		return profile.NewJWTProfileTokenSource(ctx, issuer, file.UserID, file.KeyID, file.Key, scopes)
	}
}

// JWTAuthentication 允许使用 OAuth2 JWT Profile 授权模式，
// 借助 ZITADEL 提供的服务用户 key.json 来获取令牌。
// Deprecated: 请改用 [AuthenticationJWTProfile]，它使用了正确的 KeyFile 类型。
//
//nolint:staticcheck // 为向后兼容保留该废弃签名。
func JWTAuthentication(file *client.KeyFile, scopes ...string) TokenSourceInitializer {
	return func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
		return profile.NewJWTProfileTokenSource(ctx, issuer, file.UserID, file.KeyID, []byte(file.Key), scopes)
	}
}

// PasswordAuthentication 允许使用 OAuth2 客户端凭证授权模式，
// 借助 ZITADEL 提供的服务用户名和密码来获取令牌。
func PasswordAuthentication(username, password string, scopes ...string) TokenSourceInitializer {
	return func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
		discovery, err := client.Discover(ctx, issuer, http.DefaultClient)
		if err != nil {
			return nil, err
		}
		config := &clientcredentials.Config{
			ClientID:     username,
			ClientSecret: password,
			TokenURL:     discovery.TokenEndpoint,
			Scopes:       scopes,
		}
		return config.TokenSource(ctx), nil
	}
}

// PAT 允许设置服务用户的个人访问令牌（PAT）用于授权。
func PAT(pat string) TokenSourceInitializer {
	return func(ctx context.Context, _ string) (oauth2.TokenSource, error) {
		return oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: pat,
			TokenType:   oidc.BearerToken,
		}), nil
	}
}

// DefaultServiceUserAuthentication 是 [JWTAuthentication] 的简化版本，
// 会从给定路径读取 key.json。
func DefaultServiceUserAuthentication(path string, scopes ...string) TokenSourceInitializer {
	c, err := ConfigFromKeyFile(path)
	if err != nil {
		return func(ctx context.Context, issuer string) (oauth2.TokenSource, error) {
			return nil, err
		}
	}
	return AuthenticationJWTProfile(c, scopes...)
}

// AuthorizedUserCtx 会将已授权上下文（用户）中的授权令牌设置好，
// 供后续调用使用。若不存在已授权上下文，该方法会直接原样返回传入的上下文。
func AuthorizedUserCtx(ctx context.Context) context.Context {
	authCtx := authorization.Context[authorization.Ctx](ctx)
	if !authCtx.IsAuthorized() {
		return ctx
	}
	return BearerTokenCtx(ctx, strings.TrimPrefix(authCtx.GetToken(), oidc.BearerToken))
}

// BearerTokenCtx 会设置传入的令牌，供后续调用使用。
func BearerTokenCtx(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxOverwrite, &oauth2.Token{
		AccessToken: strings.Trim(token, " "),
		TokenType:   oidc.BearerToken,
	})
}

const (
	scopeFormatProjectID  = "urn:zitadel:iam:org:project:id:%s:aud"
	scopeZITADELProjectID = "zitadel"
)

// ScopeProjectID 会将指定的 projectID 添加到访问令牌和 ID 令牌的 audience 中
func ScopeProjectID(projectID string) string {
	return fmt.Sprintf(scopeFormatProjectID, projectID)
}

// ScopeZitadelAPI 将 ZITADEL 自身的 projectID 添加到 audience 中
func ScopeZitadelAPI() string {
	return ScopeProjectID(scopeZITADELProjectID)
}

// PreSignedJWT 允许使用一个预先签发的 JWT 令牌进行授权。
// 当你已经持有一个有效的 JWT 令牌，且不希望客户端再生成并签名一个新令牌时，
// 这个方式会很有用。
func PreSignedJWT(token string) TokenSourceInitializer {
	return func(ctx context.Context, _ string) (oauth2.TokenSource, error) {
		return oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
			TokenType:   oidc.BearerToken,
		}), nil
	}
}
