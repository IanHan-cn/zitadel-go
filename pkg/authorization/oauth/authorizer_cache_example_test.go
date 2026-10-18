package oauth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
)

// GoCacheAdapter 通过包装流行的 patrickmn/go-cache 库，
// 提供了 TokenCache 接口的具体且线程安全的实现。
// 它充当了一座桥梁，使这个外部库能作为可插拔组件
// 参与到校验流程中。
type GoCacheAdapter[T any] struct {
	client *cache.Cache
}

// NewGoCacheAdapter 创建一个以 patrickmn/go-cache 作为底层存储的适配器。
// 参数用于控制缓存的淘汰策略。
func NewGoCacheAdapter[T any](defaultExpiration, cleanupInterval time.Duration) *GoCacheAdapter[T] {
	return &GoCacheAdapter[T]{
		client: cache.New(defaultExpiration, cleanupInterval),
	}
}

// Get 从缓存中取出一个值。它通过从底层缓存获取条目
// 并安全地断言为预期的泛型类型，满足了 TokenCache 接口。
func (a *GoCacheAdapter[T]) Get(token string) (T, bool) {
	var zero T
	value, found := a.client.Get(token)
	if !found {
		return zero, false
	}

	typedValue, ok := value.(T)
	if !ok {
		return zero, false
	}
	return typedValue, true
}

// Set 将一个值存入缓存。它通过将 token、value 和 TTL
// 直接传给底层缓存实例，满足了 TokenCache 接口。
func (a *GoCacheAdapter[T]) Set(token string, value T, ttl time.Duration) {
	a.client.Set(token, value, ttl)
}

// exRS 是本示例中用到的极简 ResourceServer 替身，
// 提供了满足 rs.ResourceServer 接口所必需的方法。
type exRS struct {
	client *http.Client
	url    string
}

// IntrospectionURL 返回模拟的 introspection 端点 URL。
func (e *exRS) IntrospectionURL() string {
	return e.url
}

// TokenEndpoint 返回空字符串，因为本示例不需要它。
func (e *exRS) TokenEndpoint() string {
	return ""
}

// HttpClient 返回模拟的 HTTP 客户端。
func (e *exRS) HttpClient() *http.Client {
	return e.client
}

// AuthFn 返回 nil，因为本示例不需要它。
func (e *exRS) AuthFn() (any, error) {
	return nil, nil
}

// exTransport 是一个模拟的 http.RoundTripper，它返回一个预设好的
// introspection 响应，而不会发起真实的网络调用。
type exTransport struct{}

// RoundTrip 返回一个固定的、成功的 introspection 响应。
func (t *exTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	body := []byte(`{"active": true, "sub": "alice"}`)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

// ExampleIntrospectionVerificationWithCache 演示了使用生产级缓存
// 完成一整套校验流程。它构造一个模拟的 resource server 和
// 一个 GoCacheAdapter，将它们注入新的校验器实例，
// 然后执行一次授权检查，以展示各组件协同工作的方式。
func ExampleIntrospectionVerificationWithCache() {
	mockTransport := &exTransport{}
	httpClient := &http.Client{
		Transport: mockTransport,
	}

	resourceServer := &exRS{
		client: httpClient,
		url:    "https://example.test/introspect",
	}

	type introspectionResp struct {
		Active  bool   `json:"active"`
		Subject string `json:"sub"`
	}

	cacheAdapter := NewGoCacheAdapter[introspectionResp](
		5*time.Minute,
		10*time.Minute,
	)

	verifier := NewIntrospectionVerificationWithCache(
		resourceServer,
		cacheAdapter,
		30*time.Second,
	)

	resp, err := verifier.CheckAuthorization(context.Background(), "Bearer token123")
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.Subject)
	// Output: alice
}
