package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

const (
	HeaderName = "authorization"
)

var (
	ErrEmptyAuthorizationHeader = errors.New("authorization header is empty")
	ErrMissingToken             = errors.New("missing or malformed token")
	ErrMissingRole              = errors.New("missing required role")
)

// checkForEmptyorMalformedToken 校验以下几种情况：
// 1. 令牌请求头为空
// 2. 令牌请求头不以 "Bearer " 开头
// 3. 去掉 "Bearer " 前缀后令牌为空
func checkForEmptyorMalformedToken(tokenHeader string) error {
	t := strings.TrimSpace(tokenHeader)
	token, ok := strings.CutPrefix(t, oidc.BearerToken+" ")
	if !ok || token == "" || tokenHeader == "" {
		return ErrMissingToken
	}
	return nil
}

// AuthorizationChecker 定义了用于检查授权的接口。
// 该接口便于在测试中通过 mock 替换实现。
type AuthorizationChecker[T Ctx] interface {
	CheckAuthorization(ctx context.Context, token string, options ...CheckOption) (authCtx T, err error)
}

// Authorizer 提供授权检查的能力，例如令牌校验以及角色检查。
type Authorizer[T Ctx] struct {
	verifier Verifier[T]
	logger   *slog.Logger
}

// 编译期检查，确保 Authorizer 实现了 AuthorizationChecker
var _ AuthorizationChecker[Ctx] = (*Authorizer[Ctx])(nil)

// Option 用于对 [Authorizer] 进行定制，例如缓存、日志等。
type Option[T Ctx] func(authorizer *Authorizer[T])

// WithLogger 允许使用 slog.Default() 之外的日志记录器。
//
// 实验性特性：在我们放弃对 Go 1.20 的支持后，将改为直接引入 log/slog
func WithLogger[T Ctx](logger *slog.Logger) Option[T] {
	return func(a *Authorizer[T]) {
		a.logger = logger
	}
}

func New[T Ctx](ctx context.Context, zitadel *zitadel.Zitadel, initVerifier VerifierInitializer[T], options ...Option[T]) (*Authorizer[T], error) {
	verifier, err := initVerifier(ctx, zitadel)
	if err != nil {
		return nil, err
	}
	authorizer := &Authorizer[T]{
		verifier: verifier,
		logger:   slog.Default(),
	}
	for _, option := range options {
		option(authorizer)
	}
	return authorizer, nil
}

// CheckAuthorization 会使用已配置的 [Verifier] 和提供的 [Check] 来校验令牌
func (a *Authorizer[T]) CheckAuthorization(ctx context.Context, token string, options ...CheckOption) (authCtx T, err error) {
	a.logger.Log(ctx, slog.LevelDebug, "checking authorization")
	var t T
	if err := checkForEmptyorMalformedToken(token); err != nil {
		a.logger.Log(ctx, slog.LevelWarn, "no authorization header")
		return t, NewErrorUnauthorized(err)
	}
	checks := new(Check[Ctx])
	for _, option := range options {
		option(checks)
	}
	authCtx, err = a.verifier.CheckAuthorization(ctx, token)
	if err != nil || !authCtx.IsAuthorized() {
		if err != nil && isServerError(err) {
			a.logger.With("error", err).Log(ctx, slog.LevelWarn, "service unavailable")
			return t, NewErrorServiceUnavailable(err)
		}
		a.logger.With("error", err).Log(ctx, slog.LevelWarn, "unauthorized")
		return t, NewErrorUnauthorized(err)
	}
	for _, c := range checks.Checks {
		if err = c(authCtx); err != nil {
			a.logger.With("error", err, "user", authCtx.UserID()).Log(ctx, slog.LevelWarn, "permission denied")
			return t, NewErrorPermissionDenied(err)
		}
	}
	authCtx.SetToken(token)
	return authCtx, nil
}

// Verifier 定义了可用的校验方式，例如对 authorizationToken 的验证。
type Verifier[T Ctx] interface {
	CheckAuthorization(ctx context.Context, authorizationToken string) (T, error)
}

// VerifierInitializer 抽象了 [Verifier] 的初始化过程，提供 ZITADEL 域名、端口以及是否启用 tls
type VerifierInitializer[T Ctx] func(ctx context.Context, zitadel *zitadel.Zitadel) (Verifier[T], error)

// Check 会在授权检查过程中执行，提供一种要求额外权限（例如角色）的机制。
// 不久的将来会增加更多选项，如缓存等。
type Check[T Ctx] struct {
	Checks []func(authCtx T) error
}

// CheckOption 用于对 [Check] 进行定制，例如额外的权限要求（如角色）
type CheckOption func(*Check[Ctx])

// WithRole 要求被授权的用户已被授予指定的角色。
// 若用户未被授予该角色，则返回 [ErrMissingRole]。
func WithRole(role string) CheckOption {
	return func(checks *Check[Ctx]) {
		checks.Checks = append(checks.Checks, func(authCtx Ctx) error {
			if authCtx.IsGrantedRole(role) {
				return nil
			}
			return fmt.Errorf("%w: `%s`", ErrMissingRole, role)
		})
	}
}

// isServerError 检查某个错误是否表示来自 introspection 端点的 5xx 服务端错误。
// 它会在错误信息中查找 5xx 状态码或常见的服务端错误标志。
func isServerError(err error) bool {
	if err == nil {
		return false
	}

	errorMsg := err.Error()

	// 在错误信息中查找显式的 5xx 状态码
	// 注意：当错误通过 fmt.Errorf("%w", ...) 包装时，外层错误的
	// Error() 方法会包含被包装错误的信息，因此只需检查外层错误信息即可。
	statusCodeRegex := regexp.MustCompile(`\b(5\d{2})\b`)
	matches := statusCodeRegex.FindStringSubmatch(errorMsg)
	if len(matches) > 1 {
		if _, parseErr := strconv.Atoi(matches[1]); parseErr == nil {
			return true
		}
	}

	return false
}
