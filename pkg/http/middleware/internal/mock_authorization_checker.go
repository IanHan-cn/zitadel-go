// Package internal 为 middleware 包提供内部测试工具。
package internal

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
)

// MockAuthorizationChecker 是用于测试的 authorization.AuthorizationChecker mock 实现。
// 它会返回预先配置好的上下文或错误。
type MockAuthorizationChecker struct {
	Ctx *MockAuthContext
	Err error
}

// CheckAuthorization 返回预先配置好的上下文或错误。
// 由于这是测试用的 mock，参数有意不使用。
func (m *MockAuthorizationChecker) CheckAuthorization(_ context.Context, _ string, _ ...authorization.CheckOption) (*MockAuthContext, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Ctx, nil
}

// MockAuthContext 是用于测试的 authorization.Ctx mock 实现。
// 它保存用户与组织信息，并记录角色授予情况。
type MockAuthContext struct {
	id    string
	orgID string
	token string
	roles map[string]bool
}

// NewMockAuthContext 使用指定的用户 ID 和组织 ID 创建一个新的 MockAuthContext。
func NewMockAuthContext(userID, organizationID string) *MockAuthContext {
	return &MockAuthContext{
		id:    userID,
		orgID: organizationID,
	}
}

// NewMockAuthContextWithRoles 创建一个带有角色信息的 MockAuthContext。
func NewMockAuthContextWithRoles(userID string, roles map[string]bool) *MockAuthContext {
	return &MockAuthContext{
		id:    userID,
		roles: roles,
	}
}

// SetToken 设置授权令牌。
func (m *MockAuthContext) SetToken(token string) {
	m.token = token
}

// GetToken 返回授权令牌。
func (m *MockAuthContext) GetToken() string {
	return m.token
}

// IsAuthorized 在上下文不为 nil 时返回 true。
func (m *MockAuthContext) IsAuthorized() bool {
	return m != nil
}

// OrganizationID 返回组织 ID。
func (m *MockAuthContext) OrganizationID() string {
	if m == nil {
		return ""
	}
	return m.orgID
}

// UserID 返回用户 ID。
func (m *MockAuthContext) UserID() string {
	if m == nil {
		return ""
	}
	return m.id
}

// IsGrantedRole 检查给定的角色是否已被授予。
func (m *MockAuthContext) IsGrantedRole(role string) bool {
	if m == nil || m.roles == nil {
		return false
	}
	return m.roles[role]
}

// IsGrantedRoleInOrganization 在该 mock 实现中始终返回 false。
func (m *MockAuthContext) IsGrantedRoleInOrganization(_, _ string) bool {
	return false
}

// IsGrantedRoleInProject 在该 mock 实现中始终返回 false。
func (m *MockAuthContext) IsGrantedRoleInProject(_, _, _ string) bool {
	return false
}
