package middleware

import (
	"context"
	"errors"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/metadata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
)

type Interceptor[T authorization.Ctx] struct {
	authorizer authorization.AuthorizationChecker[T]
	checks     map[string][]authorization.CheckOption
}

func New[T authorization.Ctx](authorizer authorization.AuthorizationChecker[T], checks map[string][]authorization.CheckOption) *Interceptor[T] {
	return &Interceptor[T]{
		authorizer: authorizer,
		checks:     checks,
	}
}

// Unary 创建一个 [grpc.UnaryServerInterceptor]。
// 请确保为 [Interceptor] 配置了所需的检查项。
// 若未提供任何检查项，该拦截器将允许 API 被公开访问。
func (i *Interceptor[T]) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		ctx, err = i.intercept(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream 创建一个 [grpc.StreamServerInterceptor]。
// 请确保为 [Interceptor] 配置了所需的检查项。
// 若未提供任何检查项，该拦截器将允许 API 被公开访问。
func (i *Interceptor[T]) Stream() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := i.intercept(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &serverStream{ServerStream: stream, ctx: ctx})
	}
}

// Context 包装了 [authorization.Context] 函数，
// 用于直接返回 [Interceptor] 中带有具体类型的 [authorization.Ctx]。
func (i *Interceptor[T]) Context(ctx context.Context) T {
	return authorization.Context[T](ctx)
}

func (i *Interceptor[T]) intercept(ctx context.Context, method string) (context.Context, error) {
	for endpoint, checks := range i.checks {
		if endpoint != method {
			continue
		}
		authCtx, err := i.authorizer.CheckAuthorization(ctx, metadata.ExtractIncoming(ctx).Get(authorization.HeaderName), checks...)
		if err != nil {
			if errors.Is(err, &authorization.UnauthorizedErr{}) {
				return nil, status.Error(codes.Unauthenticated, err.Error())
			}
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return authorization.WithAuthContext(ctx, authCtx), nil
	}
	return ctx, nil
}

// serverStream 的存在是为了能够在客户端调用与服务端之间
// 拦截并注入 [context.Context]。
type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context {
	return s.ctx
}
