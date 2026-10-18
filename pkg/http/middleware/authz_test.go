package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/http/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/http/middleware/internal"
)

// TestInterceptor_RequireAuthorization_Success 验证：当授权成功时，
// 处理器会被调用并返回 200 OK。
func TestInterceptor_RequireAuthorization_Success(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Ctx: internal.NewMockAuthContext("user-123", "org-456"),
	}
	interceptor := middleware.New(checker)

	var handlerCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrappedHandler := interceptor.RequireAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "success", response.Body.String())
	assert.True(t, handlerCalled)
}

// TestInterceptor_RequireAuthorization_UnauthorizedError 验证：当授权
// 返回未授权错误时，中间件会返回 401 且不会调用处理器。
func TestInterceptor_RequireAuthorization_UnauthorizedError(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorUnauthorized(errors.New("invalid token")),
	}
	interceptor := middleware.New(checker)

	var handlerCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrappedHandler := interceptor.RequireAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	request.Header.Set("Authorization", "Bearer invalid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
	assert.Equal(t, "invalid token\n", response.Body.String())
	assert.False(t, handlerCalled)
}

// TestInterceptor_RequireAuthorization_PermissionDenied 验证：当授权
// 返回权限不足错误时，中间件会返回 403 且不会调用处理器。
func TestInterceptor_RequireAuthorization_PermissionDenied(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorPermissionDenied(errors.New("insufficient permissions")),
	}
	interceptor := middleware.New(checker)

	var handlerCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrappedHandler := interceptor.RequireAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.Equal(t, "insufficient permissions\n", response.Body.String())
	assert.False(t, handlerCalled)
}

// TestInterceptor_RequireAuthorization_MissingHeader 验证：当缺少
// 授权请求头时，中间件会返回 401 且不会调用处理器。
func TestInterceptor_RequireAuthorization_MissingHeader(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorUnauthorized(errors.New("missing token")),
	}
	interceptor := middleware.New(checker)

	var handlerCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	wrappedHandler := interceptor.RequireAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
	assert.Equal(t, "missing token\n", response.Body.String())
	assert.False(t, handlerCalled)
}

// TestInterceptor_CheckAuthorization_Success 验证：当授权成功时，
// 处理器会被调用，且请求上下文中已注入授权上下文。
func TestInterceptor_CheckAuthorization_Success(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Ctx: internal.NewMockAuthContext("user-123", "org-456"),
	}
	interceptor := middleware.New(checker)

	var (
		handlerCalled bool
		handlerCtx    context.Context
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		handlerCtx = r.Context()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("handler executed"))
	})

	wrappedHandler := interceptor.CheckAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/optional-auth", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	require.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "handler executed", response.Body.String())

	authCtx := authorization.Context[*internal.MockAuthContext](handlerCtx)
	require.NotNil(t, authCtx)
	assert.Equal(t, "user-123", authCtx.UserID())
}

// TestInterceptor_CheckAuthorization_FailedAuth 验证：当授权失败时，
// 处理器仍会被调用，但请求上下文中不含授权上下文。
func TestInterceptor_CheckAuthorization_FailedAuth(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorUnauthorized(errors.New("invalid token")),
	}
	interceptor := middleware.New(checker)

	var (
		handlerCalled bool
		handlerCtx    context.Context
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		handlerCtx = r.Context()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("handler executed"))
	})

	wrappedHandler := interceptor.CheckAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/optional-auth", nil)
	request.Header.Set("Authorization", "Bearer invalid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	require.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "handler executed", response.Body.String())

	authCtx := authorization.Context[*internal.MockAuthContext](handlerCtx)
	assert.Nil(t, authCtx)
}

// TestInterceptor_CheckAuthorization_PermissionDenied 验证：当授权
// 返回权限不足错误时，处理器仍会被调用，但请求上下文中不含授权上下文。
func TestInterceptor_CheckAuthorization_PermissionDenied(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorPermissionDenied(errors.New("insufficient permissions")),
	}
	interceptor := middleware.New(checker)

	//goland:noinspection DuplicatedCode
	var (
		handlerCalled bool
		handlerCtx    context.Context
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		handlerCtx = r.Context()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("handler executed"))
	})

	wrappedHandler := interceptor.CheckAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/optional-auth", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	require.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "handler executed", response.Body.String())

	authCtx := authorization.Context[*internal.MockAuthContext](handlerCtx)
	assert.Nil(t, authCtx)
}

// TestInterceptor_CheckAuthorization_MissingHeader 验证：当缺少授权请求头时，
// 处理器仍会被调用，但请求上下文中不含授权上下文。
func TestInterceptor_CheckAuthorization_MissingHeader(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Err: authorization.NewErrorUnauthorized(errors.New("missing token")),
	}
	interceptor := middleware.New(checker)

	var (
		handlerCalled bool
		handlerCtx    context.Context
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		handlerCtx = r.Context()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("handler executed"))
	})

	wrappedHandler := interceptor.CheckAuthorization()(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/optional-auth", nil)
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	require.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "handler executed", response.Body.String())

	authCtx := authorization.Context[*internal.MockAuthContext](handlerCtx)
	assert.Nil(t, authCtx)
}

// TestInterceptor_CheckAuthorization_WithOptions 验证 CheckAuthorization
// 能够接收并正确透传诸如角色要求之类的授权选项。
func TestInterceptor_CheckAuthorization_WithOptions(t *testing.T) {
	checker := &internal.MockAuthorizationChecker{
		Ctx: internal.NewMockAuthContextWithRoles("admin-user", map[string]bool{
			"admin": true,
		}),
	}
	interceptor := middleware.New(checker)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx := authorization.Context[*internal.MockAuthContext](r.Context())
		if authCtx != nil && authCtx.IsGrantedRole("admin") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin access granted"))
		} else {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("not admin"))
		}
	})

	wrappedHandler := interceptor.CheckAuthorization(authorization.WithRole("admin"))(handler)

	request := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
	request.Header.Set("Authorization", "Bearer admin-token")
	response := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "admin access granted", response.Body.String())
}

// TestInterceptor_Context 验证 Context 方法能够
// 从请求上下文中正确取出授权上下文。
func TestInterceptor_Context(t *testing.T) {
	expectedAuthCtx := internal.NewMockAuthContext("user-123", "org-456")

	ctx := authorization.WithAuthContext(context.Background(), expectedAuthCtx)
	checker := &internal.MockAuthorizationChecker{Ctx: expectedAuthCtx}
	interceptor := middleware.New(checker)

	retrievedAuthCtx := interceptor.Context(ctx)

	assert.Equal(t, expectedAuthCtx, retrievedAuthCtx)
	assert.Equal(t, "user-123", retrievedAuthCtx.UserID())
	assert.Equal(t, "org-456", retrievedAuthCtx.OrganizationID())
}
