package authorization

import "context"

type key int

const (
	ctxKey key = 1
)

// Ctx 表示授权上下文，包含已授权用户的信息。
type Ctx interface {
	IsAuthorized() bool
	OrganizationID() string
	UserID() string
	IsGrantedRole(role string) bool
	IsGrantedRoleInProject(projectID, role, organizationID string) bool
	IsGrantedRoleInOrganization(role, organizationID string) bool
	SetToken(token string)
	GetToken() string
}

// Context 返回授权上下文 [Ctx] 的具体类型实现。
// 可用它来获取（已授权的）用户/调用方的信息。
func Context[T Ctx](ctx context.Context) (t T) {
	authCtx, ok := ctx.Value(ctxKey).(T)
	if !ok {
		return t
	}
	return authCtx
}

// IsAuthorized 返回调用方是否已获得授权
func IsAuthorized(ctx context.Context) bool {
	return Context[Ctx](ctx).IsAuthorized()
}

// OrganizationID 返回已授权用户所属组织的 ID。
func OrganizationID(ctx context.Context) string {
	return Context[Ctx](ctx).OrganizationID()
}

// UserID 返回已授权用户的 ID。
// 若调用方未获授权，则该 ID 为空。
func UserID(ctx context.Context) string {
	return Context[Ctx](ctx).UserID()
}

// IsGrantedRole 返回已授权用户是否被授予了所请求的角色。
// 若调用方未获授权，则返回 false。
func IsGrantedRole(ctx context.Context, role string) bool {
	return Context[Ctx](ctx).IsGrantedRole(role)
}

// IsGrantedRoleInOrganization 返回已授权用户是否在指定组织内被授予了所请求的角色。
// 若调用方未获授权，则返回 false。
func IsGrantedRoleInOrganization(ctx context.Context, role, organisationID string) bool {
	return Context[Ctx](ctx).IsGrantedRoleInOrganization(role, organisationID)
}

// WithAuthContext 允许设置授权上下文（[Ctx]），
// 之后可通过调用 [Context] 函数将其取出。
func WithAuthContext[T Ctx](ctx context.Context, c T) context.Context {
	return context.WithValue(ctx, ctxKey, c)
}
