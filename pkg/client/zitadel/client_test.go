package zitadel

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// startMockGRPCServer 搭建一个极简的、不具备实际功能的 gRPC 服务器，
// 但能成功接受连接。这样我们就能测试 NewConnection 函数的逻辑，
// 而不会让它在 `grpc.Dial` 处失败。
func startMockGRPCServer(t *testing.T) string {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "mock server failed to listen")

	s := grpc.NewServer()

	go func() {
		_ = s.Serve(lis)
	}()

	t.Cleanup(s.GracefulStop)

	return lis.Addr().String()
}

// TestWithCustomURL 验证 WithCustomURL 选项能否正确覆盖
// Connection 结构体中默认的 issuer 和 api 端点值。
func TestWithCustomURL(t *testing.T) {
	api := startMockGRPCServer(t)
	customIssuer := "https://my-custom-issuer.com"
	customAPI := "my-custom-api.com:443"

	conn, err := NewConnection(context.Background(), "default-issuer", api, nil,
		WithCustomURL(customIssuer, customAPI),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Equal(t, customIssuer, conn.issuer)
	assert.Equal(t, customAPI, conn.api)
}

// TestWithTokenSource 验证 WithTokenSource 选项能否在 Connection 结构体上
// 正确设置一个通用的 oauth2.TokenSource。
func TestWithTokenSource(t *testing.T) {
	api := startMockGRPCServer(t)
	mockTokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"})

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithTokenSource(mockTokenSource),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Equal(t, mockTokenSource, conn.tokenSource)
}

// TestWithInsecure 验证 WithInsecure 选项能否正确将内部的 insecure 标志设为 true。
func TestWithInsecure(t *testing.T) {
	api := startMockGRPCServer(t)

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithInsecure(),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.True(t, conn.insecure)
}

// TestWithInsecureSkipVerifyTLS 验证 WithInsecureSkipVerifyTLS 选项
// 能否在连接上正确设置该标志。
func TestWithInsecureSkipVerifyTLS(t *testing.T) {
	api := startMockGRPCServer(t)

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithInsecureSkipVerifyTLS(),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.True(t, conn.insecureSkipVerify)
}

// TestWithTransportHeader 验证传输层请求头是否已保存在连接上。
func TestWithTransportHeader(t *testing.T) {
	api := startMockGRPCServer(t)

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithTransportHeader("x-test", "value"),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Equal(t, "value", conn.transportHeaders["x-test"])
}

// TestWithUnaryInterceptors 验证 WithUnaryInterceptors 选项能否
// 将自定义 gRPC 拦截器正确追加到连接的拦截器列表中。
func TestWithUnaryInterceptors(t *testing.T) {
	api := startMockGRPCServer(t)
	dummyInterceptor := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return status.Error(codes.Unimplemented, "dummy interceptor")
	}

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithUnaryInterceptors(dummyInterceptor, dummyInterceptor),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Len(t, conn.unaryInterceptors, 3)
}

// TestWithStreamInterceptors 验证 WithStreamInterceptors 选项能否
// 将自定义 gRPC 拦截器正确追加到连接的拦截器列表中。
func TestWithStreamInterceptors(t *testing.T) {
	api := startMockGRPCServer(t)
	dummyInterceptor := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return nil, status.Error(codes.Unimplemented, "dummy interceptor")
	}

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithStreamInterceptors(dummyInterceptor, dummyInterceptor),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Len(t, conn.streamInterceptors, 3)
}

// TestWithDialOptions 验证 WithDialOptions 选项能否
// 正确追加自定义的 gRPC 拨号选项。
func TestWithDialOptions(t *testing.T) {
	api := startMockGRPCServer(t)
	dummyDialOption := grpc.WithUserAgent("my-test-agent/1.0")

	conn, err := NewConnection(context.Background(), "issuer", api, nil,
		WithDialOptions(dummyDialOption),
		WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{})),
	)
	require.NoError(t, err, "NewConnection should not fail")

	assert.Len(t, conn.dialOptions, 1)
}
