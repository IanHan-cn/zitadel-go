// Package internal 为 authentication 包提供内部测试工具。
package internal

import (
	"errors"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
)

// MockSessionStore 是用于测试的会话存储 mock 实现。
// 它将会话保存在内存中，并记录 Set 和 Get 方法是否被调用过。
type MockSessionStore[T authentication.Ctx] struct {
	SetCalled bool
	GetCalled bool
	Store     map[string]T
}

// NewMockSessionStore 创建一个存储映射已初始化的 MockSessionStore。
func NewMockSessionStore[T authentication.Ctx]() *MockSessionStore[T] {
	return &MockSessionStore[T]{
		Store: make(map[string]T),
	}
}

// Set 按给定的 ID 保存会话，并将 SetCalled 标记为 true。
func (m *MockSessionStore[T]) Set(id string, session T) error {
	m.SetCalled = true
	m.Store[id] = session
	return nil
}

// Get 按 ID 取出会话，并将 GetCalled 标记为 true。
// 若未找到对应的会话 ID，则返回错误。
func (m *MockSessionStore[T]) Get(id string) (T, error) {
	m.GetCalled = true
	s, ok := m.Store[id]
	if !ok {
		var zero T
		return zero, errors.New("session not found")
	}
	return s, nil
}
