package middleware

import (
	"context"
	"errors"
	"os"

	"github.com/zitadel/oidc/v3/pkg/client/profile"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
)

const (
	ZitadelKeyPath = "ZITADEL_KEY_PATH"
)

func OSKeyPath() string {
	return os.Getenv(ZitadelKeyPath)
}

type AuthInterceptor struct {
	oauth2.TokenSource
}

type JWTProfileTokenSource func(issuer string, scopes []string) (oauth2.TokenSource, error)
type JWTDirectTokenSource func() (oauth2.TokenSource, error)

func JWTProfileFromPath(ctx context.Context, keyPath string) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFile(keyPath)
		if err != nil {
			return nil, err
		}
		return JWTProfileFromKeyAndUserID(ctx, keyData.Key, keyData.KeyID, keyData.UserID)(issuer, scopes)
	}
}

func JWTProfileFromFileData(ctx context.Context, fileData []byte) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		keyData, err := client.ConfigFromKeyFileData(fileData)
		if err != nil {
			return nil, err
		}
		return JWTProfileFromKeyAndUserID(ctx, keyData.Key, keyData.KeyID, keyData.UserID)(issuer, scopes)
	}
}

func JWTProfileFromKeyAndUserID(ctx context.Context, key []byte, keyID, userID string) JWTProfileTokenSource {
	return func(issuer string, scopes []string) (oauth2.TokenSource, error) {
		return profile.NewJWTProfileTokenSource(ctx, issuer, userID, keyID, key, scopes)
	}
}

// NewGenericAuthenticator 基于任意提供的 oauth2.TokenSource 创建一个拦截器。
// 这是最灵活的构造函数，可支持客户端凭证、个人访问令牌
// 或其他自定义令牌来源等使用场景。
func NewGenericAuthenticator(ts oauth2.TokenSource) (*AuthInterceptor, error) {
	if ts == nil {
		return nil, errors.New("token source cannot be nil")
	}
	return &AuthInterceptor{
		TokenSource: oauth2.ReuseTokenSource(nil, ts),
	}, nil
}

// NewAuthenticator 创建一个拦截器，使用提供的 JWT Profile 对服务账号进行认证
// （key.json 可以以文件或数据的形式提供）。
// 返回的令牌将用于所有调用的授权；
// 若令牌过期，会自动刷新。
func NewAuthenticator(issuer string, jwtProfileTokenSource JWTProfileTokenSource, scopes ...string) (*AuthInterceptor, error) {
	ts, err := jwtProfileTokenSource(issuer, scopes)
	if err != nil {
		return nil, err
	}
	return &AuthInterceptor{
		TokenSource: oauth2.ReuseTokenSource(nil, ts),
	}, nil
}

func NewPresignedJWTAuthenticator(jwtDirectTokenSource JWTDirectTokenSource) (*AuthInterceptor, error) {
	ts, err := jwtDirectTokenSource()
	if err != nil {
		return nil, err
	}
	return &AuthInterceptor{
		TokenSource: oauth2.ReuseTokenSource(nil, ts),
	}, nil
}

func (interceptor *AuthInterceptor) Unary() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		authCtx, err := interceptor.setToken(ctx)
		if err != nil {
			return err
		}
		return invoker(authCtx, method, req, reply, cc, opts...)
	}
}

func (interceptor *AuthInterceptor) Stream() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		authCtx, err := interceptor.setToken(ctx)
		if err != nil {
			return nil, err
		}
		return streamer(authCtx, desc, cc, method, opts...)
	}
}

func (interceptor *AuthInterceptor) setToken(ctx context.Context) (context.Context, error) {
	token, err := interceptor.Token()
	if err != nil {
		return ctx, err
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", token.TokenType+" "+token.AccessToken), nil
}
