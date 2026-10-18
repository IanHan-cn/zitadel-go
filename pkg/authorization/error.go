package authorization

import (
	"errors"
)

// UnauthorizedErr 用于告知调用方：所提供的授权信息无效（缺失、格式错误、已过期等）。
type UnauthorizedErr struct {
	err error
}

func NewErrorUnauthorized(err error) *UnauthorizedErr {
	return &UnauthorizedErr{
		err: err,
	}
}

func (e *UnauthorizedErr) Error() string {
	if e.err == nil {
		return "unauthorized"
	}
	return e.err.Error()
}

func (e *UnauthorizedErr) Is(target error) bool {
	t, ok := target.(*UnauthorizedErr)
	if !ok {
		return false
	}
	if t.err == nil {
		return true
	}
	return errors.Is(e.err, t.err)
}

func (e *UnauthorizedErr) Unwrap() error {
	return e.err
}

// PermissionDeniedErr 用于告知调用方：所提供的授权信息有效但不充分（缺少角色）。
type PermissionDeniedErr struct {
	err error
}

func NewErrorPermissionDenied(err error) *PermissionDeniedErr {
	return &PermissionDeniedErr{
		err: err,
	}
}

func (e *PermissionDeniedErr) Error() string {
	if e.err == nil {
		return "permission denied"
	}
	return e.err.Error()
}

func (e *PermissionDeniedErr) Is(target error) bool {
	t, ok := target.(*PermissionDeniedErr)
	if !ok {
		return false
	}
	if t.err == nil {
		return true
	}
	return errors.Is(e.err, t.err)
}

func (e *PermissionDeniedErr) Unwrap() error {
	return e.err
}

// ServiceUnavailableErr 用于表示授权服务暂时不可用（5xx 错误）。
// 这使得下游代码能够区分客户端错误（4xx）与服务端错误（5xx）。
type ServiceUnavailableErr struct {
	err error
}

func NewErrorServiceUnavailable(err error) *ServiceUnavailableErr {
	return &ServiceUnavailableErr{
		err: err,
	}
}

func (e *ServiceUnavailableErr) Error() string {
	if e.err == nil {
		return "service unavailable"
	}
	return e.err.Error()
}

func (e *ServiceUnavailableErr) Is(target error) bool {
	t, ok := target.(*ServiceUnavailableErr)
	if !ok {
		return false
	}
	if t.err == nil {
		return true
	}
	return errors.Is(e.err, t.err)
}

func (e *ServiceUnavailableErr) Unwrap() error {
	return e.err
}
