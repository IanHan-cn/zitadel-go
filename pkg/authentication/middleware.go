package authentication

import (
	"context"
	"net/http"
)

type Interceptor[T Ctx] struct {
	authenticator AuthenticationChecker[T]
}

func Middleware[T Ctx](authenticator AuthenticationChecker[T]) *Interceptor[T] {
	return &Interceptor[T]{
		authenticator: authenticator,
	}
}

// RequireAuthentication 会检查是否存在有效会话，并将其放入上下文中。
// 若不存在会话，它会自动发起一次新的认证（将用户重定向到登录界面）
func (i *Interceptor[T]) RequireAuthentication() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, err := i.authenticator.IsAuthenticated(req)
			if err != nil {
				i.authenticator.Authenticate(w, req, req.RequestURI)
				return
			}
			req = req.WithContext(WithAuthContext(req.Context(), ctx))
			next.ServeHTTP(w, req)
		})
	}
}

// CheckAuthentication 会检查是否存在有效会话，并将其放入上下文中。
// 与 [RequireAuthentication] 不同，当会话不存在时它不会发起新的认证。
func (i *Interceptor[T]) CheckAuthentication() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx, err := i.authenticator.IsAuthenticated(req)
			if err == nil {
				req = req.WithContext(WithAuthContext(req.Context(), ctx))
			}
			next.ServeHTTP(w, req)
		})
	}
}

func (i *Interceptor[T]) Context(ctx context.Context) T {
	return Context[T](ctx)
}
