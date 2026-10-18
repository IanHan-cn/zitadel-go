package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rs"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TokenCache 定义了用于缓存 introspection 结果的最小接口。
// 实现必须是并发安全的。TTL 用于告知缓存该条目在被清除前应保持有效的时长。
type TokenCache[T any] interface {
	// Get 返回 token 对应的缓存值（若存在且未过期）。
	// 若不存在或已过期，则 ok 为 false，并返回零值。
	Get(token string) (v T, ok bool)

	// Set 按给定的 TTL 保存 token 对应的值。实现
	// 应确保在 TTL 到期后该条目失效。
	Set(token string, value T, ttl time.Duration)
}

// IntrospectionVerificationWithCache 使用 OAuth2 introspection 端点校验 bearer 令牌，
// 并可选地缓存结果，以避免在配置的 TTL 内对相同令牌重复发起网络调用。
// 若 cache 为 nil，则所有调用都会直接访问 introspection 端点。
type IntrospectionVerificationWithCache[T any] struct {
	rs    rs.ResourceServer
	cache TokenCache[T]
	ttl   time.Duration
}

// NewIntrospectionVerificationWithCache 构造一个校验器，它使用提供的
// ResourceServer 进行 introspection，并可选地使用缓存以在指定的 TTL 内复用结果。
// 若 cache 为 nil，则不进行任何缓存。
func NewIntrospectionVerificationWithCache[T any](
	rs rs.ResourceServer,
	cache TokenCache[T],
	ttl time.Duration,
) *IntrospectionVerificationWithCache[T] {
	return &IntrospectionVerificationWithCache[T]{
		rs:    rs,
		cache: cache,
		ttl:   ttl,
	}
}

// CheckAuthorization 校验 authorizationToken，其值必须以 "Bearer " 开头。
// 若配置了缓存且存在缓存结果，则直接返回该结果；
// 否则会调用 introspection 端点，并将响应按配置的 TTL 存入缓存。
func (v *IntrospectionVerificationWithCache[T]) CheckAuthorization(
	ctx context.Context,
	authorizationToken string,
) (resp T, err error) {
	var zero T

	token, ok := strings.CutPrefix(authorizationToken, oidc.BearerToken)
	if !ok {
		return zero, ErrInvalidAuthorizationHeader
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return zero, ErrInvalidAuthorizationHeader
	}

	if v.cache != nil {
		if cached, found := v.cache.Get(token); found {
			return cached, nil
		}
	}

	resp, err = rs.Introspect[T](ctx, v.rs, token)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", ErrIntrospectionFailed, err)
	}

	if v.cache != nil {
		v.cache.Set(token, resp, v.ttl)
	}
	return resp, nil
}
