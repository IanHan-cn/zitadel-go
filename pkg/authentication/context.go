package authentication

import "context"

type key int

const (
	ctxKey key = 1
)

// Ctx 表示认证上下文，包含已认证用户的信息。
type Ctx interface {
	IsAuthenticated() bool
}

// Context 返回认证上下文 [Ctx] 的具体类型实现。
// 可用它来获取（已认证）用户的信息。
func Context[T Ctx](ctx context.Context) (t T) {
	authCtx, ok := ctx.Value(ctxKey).(T)
	if !ok {
		return t
	}
	return authCtx
}

// IsAuthenticated 返回用户是否已通过认证
func IsAuthenticated(ctx context.Context) bool {
	authCtx := Context[Ctx](ctx)
	if authCtx == nil {
		return false
	}
	return authCtx.IsAuthenticated()
}

// WithAuthContext 允许设置认证上下文（[Ctx]），
// 之后可通过调用 [Context] 函数将其取出。
func WithAuthContext[T Ctx](ctx context.Context, c T) context.Context {
	return context.WithValue(ctx, ctxKey, c)
}
