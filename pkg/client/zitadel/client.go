package zitadel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
)

type Connection struct {
	issuer                string
	api                   string
	jwtProfileTokenSource middleware.JWTProfileTokenSource
	jwtDirectTokenSource  middleware.JWTDirectTokenSource
	tokenSource           oauth2.TokenSource
	scopes                []string
	orgID                 string
	insecure              bool
	insecureSkipVerify    bool
	transportHeaders      map[string]string
	unaryInterceptors     []grpc.UnaryClientInterceptor
	streamInterceptors    []grpc.StreamClientInterceptor
	dialOptions           []grpc.DialOption
	*grpc.ClientConn
}

func NewConnection(ctx context.Context, issuer, api string, scopes []string, options ...Option) (*Connection, error) {
	c := &Connection{
		issuer:                issuer,
		api:                   api,
		jwtProfileTokenSource: middleware.JWTProfileFromPath(ctx, middleware.OSKeyPath()),
		scopes:                scopes,
		transportHeaders:      make(map[string]string),
	}

	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}

	err := c.setInterceptors(c.issuer, c.orgID, c.scopes, c.jwtProfileTokenSource)
	if err != nil {
		return nil, err
	}
	if len(c.transportHeaders) > 0 {
		headerUnary := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			for k, v := range c.transportHeaders {
				ctx = metadata.AppendToOutgoingContext(ctx, k, v)
			}
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		headerStream := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			for k, v := range c.transportHeaders {
				ctx = metadata.AppendToOutgoingContext(ctx, k, v)
			}
			return streamer(ctx, desc, cc, method, opts...)
		}
		c.unaryInterceptors = append(c.unaryInterceptors, headerUnary)
		c.streamInterceptors = append(c.streamInterceptors, headerStream)
	}

	dialOptions := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(
			c.unaryInterceptors...,
		),
		grpc.WithChainStreamInterceptor(
			c.streamInterceptors...,
		),
	}
	dialOptions = append(dialOptions, c.dialOptions...)
	opt, err := transportOption(c.api, c.insecure, c.insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	dialOptions = append(dialOptions, opt)
	//nolint:staticcheck // 为与现有用法保持兼容，仍保留 grpc.Dial。
	conn, err := grpc.Dial(c.api, dialOptions...)
	if err != nil {
		return nil, err
	}
	c.ClientConn = conn

	return c, nil
}

func (c *Connection) setInterceptors(issuer, orgID string, scopes []string, jwtProfileTokenSource middleware.JWTProfileTokenSource) error {
	var auth *middleware.AuthInterceptor
	var err error
	if c.tokenSource != nil {
		auth, err = middleware.NewGenericAuthenticator(c.tokenSource)
	} else if c.jwtDirectTokenSource != nil {
		auth, err = middleware.NewPresignedJWTAuthenticator(c.jwtDirectTokenSource)
	} else {
		auth, err = middleware.NewAuthenticator(c.issuer, c.jwtProfileTokenSource, c.scopes...)
	}
	if err != nil {
		return err
	}

	c.unaryInterceptors = append(c.unaryInterceptors, auth.Unary())
	c.streamInterceptors = append(c.streamInterceptors, auth.Stream())
	if orgID != "" {
		org := middleware.NewOrgInterceptor(orgID)
		c.unaryInterceptors = append(c.unaryInterceptors, org.Unary())
		c.streamInterceptors = append(c.streamInterceptors, org.Stream())
	}
	return nil
}

func transportOption(api string, insecure bool, insecureSkipVerify bool) (grpc.DialOption, error) {
	if insecure {
		//nolint:staticcheck // 使用 WithInsecure 是为了兼容性；安全性由调用方自行把控。
		return grpc.WithInsecure(), nil
	}
	certs, err := transportCredentials(api, insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(certs), nil
}

func transportCredentials(api string, insecureSkipVerify bool) (credentials.TransportCredentials, error) {
	ca, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if ca == nil {
		ca = x509.NewCertPool()
	}

	servernameWithoutPort := strings.Split(api, ":")[0]
	tlsConfig := &tls.Config{
		RootCAs:            ca,
		InsecureSkipVerify: insecureSkipVerify,
		ServerName:         servernameWithoutPort,
	}
	return credentials.NewTLS(tlsConfig), nil
}

type Option func(*Connection) error

// WithCustomURL 用于替换默认的 issuer（https://issuer.zitadel.ch）
// 和 api 端点（api.zitadel.ch:443）
func WithCustomURL(issuer, api string) func(*Connection) error {
	return func(client *Connection) error {
		client.issuer = issuer
		client.api = api
		return nil
	}
}

// WithTokenSource 设置一个通用的 oauth2.TokenSource 用于认证。
// 这是最灵活的选项，应优先使用。
// 若设置了该选项，其优先级高于 WithJWTProfileTokenSource 或 WithJWTDirectTokenSource。
func WithTokenSource(ts oauth2.TokenSource) Option {
	return func(c *Connection) error {
		c.tokenSource = ts
		return nil
	}
}

// WithJWTProfileTokenSource 设置用于认证的 provider；
// 若未设置，则会从环境变量 ZITADEL_KEY_PATH 指定的路径读取密钥文件
func WithJWTProfileTokenSource(provider middleware.JWTProfileTokenSource) func(*Connection) error {
	return func(client *Connection) error {
		client.jwtProfileTokenSource = provider
		return nil
	}
}

// WithJWTDirectTokenSource 使用一个预先签发的 JWT 进行认证
func WithJWTDirectTokenSource(jwt string) func(*Connection) error {
	return func(client *Connection) error {
		client.jwtDirectTokenSource = func() (oauth2.TokenSource, error) {
			return oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: jwt,
				TokenType:   oidc.BearerToken,
			}), nil
		}
		return nil
	}
}

// WithOrgID 设置组织上下文（即 API 调用在哪个组织下执行）；
// 若未设置，则使用调用用户所属的资源所有者（组织）
func WithOrgID(orgID string) func(*Connection) error {
	return func(client *Connection) error {
		client.orgID = orgID
		return nil
	}
}

// WithInsecure 关闭客户端连接的传输层安全；
// 仅在确有必要时使用（例如本地开发）
func WithInsecure() func(*Connection) error {
	return func(client *Connection) error {
		client.insecure = true
		return nil
	}
}

// WithInsecureSkipVerifyTLS 在使用 TLS 时跳过证书校验。
// 仅用于使用自签名证书的本地开发场景。
func WithInsecureSkipVerifyTLS() func(*Connection) error {
	return func(client *Connection) error {
		client.insecureSkipVerify = true
		return nil
	}
}

// WithTransportHeader 为发出的 gRPC 请求设置自定义请求头。
func WithTransportHeader(key, value string) func(*Connection) error {
	return func(client *Connection) error {
		client.transportHeaders[key] = value
		return nil
	}
}

// WithUnaryInterceptors 向连接中添加非 ZITADEL 特有的拦截器
func WithUnaryInterceptors(interceptors ...grpc.UnaryClientInterceptor) func(*Connection) error {
	return func(client *Connection) error {
		client.unaryInterceptors = append(client.unaryInterceptors, interceptors...)
		return nil
	}
}

// WithStreamInterceptors 向连接中添加非 ZITADEL 特有的拦截器
func WithStreamInterceptors(interceptors ...grpc.StreamClientInterceptor) func(*Connection) error {
	return func(client *Connection) error {
		client.streamInterceptors = append(client.streamInterceptors, interceptors...)
		return nil
	}
}

// WithDialOptions 向连接中添加非 ZITADEL 特有的拨号选项
func WithDialOptions(opts ...grpc.DialOption) func(*Connection) error {
	return func(client *Connection) error {
		client.dialOptions = append(client.dialOptions, opts...)
		return nil
	}
}
