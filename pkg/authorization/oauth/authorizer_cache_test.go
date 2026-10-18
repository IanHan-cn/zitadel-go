package oauth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCache 是一个极简的、非线程安全的 TTL 缓存，
// 专为同步的单 goroutine 单元测试而设计。
type testCache[T any] struct {
	store map[string]cacheEntry[T]
	ttl   time.Duration
}

// cacheEntry 保存一个值及其过期时间。
type cacheEntry[T any] struct {
	v         T
	expiresAt time.Time
}

// newTestCache 创建并返回一个新的 testCache 实例。
func newTestCache[T any](ttl time.Duration) *testCache[T] {
	return &testCache[T]{store: make(map[string]cacheEntry[T]), ttl: ttl}
}

// Get 在缓存条目存在且未过期时，从缓存中取出对应的值。
func (c *testCache[T]) Get(token string) (T, bool) {
	entry, ok := c.store[token]
	if !ok || time.Now().After(entry.expiresAt) {
		var zero T
		return zero, false
	}
	return entry.v, true
}

// Set 按指定的 TTL 将一个值写入缓存。
func (c *testCache[T]) Set(token string, value T, ttl time.Duration) {
	c.store[token] = cacheEntry[T]{v: value, expiresAt: time.Now().Add(ttl)}
}

// testIntrospectionResp 是 introspection 的模拟响应结构体，
// 仅包含测试断言所需的最少字段。
type testIntrospectionResp struct {
	Active  bool   `json:"active,omitempty"`
	Subject string `json:"sub,omitempty"`
}

// mockResourceServerCache 是 rs.ResourceServer 接口的 mock 实现，
// 用于测试带缓存的授权校验器。
type mockResourceServerCache struct {
	client *http.Client
	url    string
}

func (m *mockResourceServerCache) IntrospectionURL() string { return m.url }
func (m *mockResourceServerCache) TokenEndpoint() string    { return "" }
func (m *mockResourceServerCache) HttpClient() *http.Client { return m.client }
func (m *mockResourceServerCache) AuthFn() (any, error)     { return nil, nil }

// mockHTTPTransportCache 是一个模拟的 http.RoundTripper，
// 它返回一个预设好的响应，并记录被调用的次数。
type mockHTTPTransportCache struct {
	respBody []byte
	status   int
	calls    int
}

// RoundTrip 递增调用计数器，并返回一个固定的 HTTP 响应。
func (m *mockHTTPTransportCache) RoundTrip(_ *http.Request) (*http.Response, error) {
	m.calls++
	return &http.Response{
		StatusCode: m.status,
		Body:       io.NopCloser(bytes.NewReader(m.respBody)),
	}, nil
}

// TestIntrospectionVerificationWithCache_CheckAuthorization 采用表驱动的方式
// 验证 CheckAuthorization 方法的缓存行为，
// 以确保各测试用例完全隔离，避免状态泄漏。
func TestIntrospectionVerificationWithCache_CheckAuthorization(t *testing.T) {
	mockRespBody := []byte(`{"active": true, "sub": "sub-from-http"}`)

	testCases := []struct {
		name              string
		token             string
		setupCache        func(c *testCache[*testIntrospectionResp])
		expectedSubject   string
		expectedHTTPCalls int
	}{
		{
			name:              "token is not in cache",
			token:             "Bearer new-token",
			setupCache:        func(c *testCache[*testIntrospectionResp]) {},
			expectedSubject:   "sub-from-http",
			expectedHTTPCalls: 1,
		},
		{
			name:  "token is found in cache and not expired",
			token: "Bearer cached-token",
			setupCache: func(c *testCache[*testIntrospectionResp]) {
				resp := &testIntrospectionResp{Active: true, Subject: "sub-from-cache"}
				c.Set("cached-token", resp, time.Minute)
			},
			expectedSubject:   "sub-from-cache",
			expectedHTTPCalls: 0,
		},
		{
			name:  "token is found in cache but is expired",
			token: "Bearer expired-token",
			setupCache: func(c *testCache[*testIntrospectionResp]) {
				resp := &testIntrospectionResp{Active: true, Subject: "sub-from-cache"}
				c.Set("expired-token", resp, -1*time.Minute)
			},
			expectedSubject:   "sub-from-http",
			expectedHTTPCalls: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTransport := &mockHTTPTransportCache{
				respBody: mockRespBody,
				status:   200,
			}
			resourceServer := &mockResourceServerCache{
				client: &http.Client{Transport: mockTransport},
				url:    "https://example.test/introspect",
			}
			cache := newTestCache[*testIntrospectionResp](time.Minute)
			tc.setupCache(cache)

			verifier := NewIntrospectionVerificationWithCache[*testIntrospectionResp](resourceServer, cache, 30*time.Second)

			out, err := verifier.CheckAuthorization(context.Background(), tc.token)

			require.NoError(t, err)
			assert.Equal(t, tc.expectedSubject, out.Subject)
			assert.Equal(t, tc.expectedHTTPCalls, mockTransport.calls)
		})
	}
}
