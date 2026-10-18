package oauth

import "github.com/zitadel/oidc/v3/pkg/oidc"

// IntrospectionContext 以 [oidc.IntrospectionResponse] 作为底层数据，实现了 [authorization.Ctx] 接口。
type IntrospectionContext struct {
	oidc.IntrospectionResponse
	token string
}

// IsAuthorized 通过检查 [oidc.IntrospectionResponse] 的 `active` 声明，实现了 [authorization.Ctx]。
func (c *IntrospectionContext) IsAuthorized() bool {
	if c == nil {
		return false
	}
	return c.Active
}

// OrganizationID 通过返回 [oidc.IntrospectionResponse] 的
// `urn:zitadel:iam:user:resourceowner:id` 声明，实现了 [authorization.Ctx]。
func (c *IntrospectionContext) OrganizationID() string {
	if c == nil {
		return ""
	}
	// 当使用 scope "urn:zitadel:iam:user:resourceowner" 时，从中提取组织 ID
	orgID, _ := c.Claims["urn:zitadel:iam:user:resourceowner:id"].(string)
	return orgID
}

// UserID 通过返回 [oidc.IntrospectionResponse] 的 `sub` 声明，实现了 [authorization.Ctx]。
func (c *IntrospectionContext) UserID() string {
	if c == nil {
		return ""
	}
	return c.Subject
}

// IsGrantedRole 通过检查 `urn:zitadel:iam:org:project:roles` 声明是否包含所请求的角色，
// 实现了 [authorization.Ctx]。
func (c *IntrospectionContext) IsGrantedRole(role string) bool {
	if c == nil {
		return false
	}
	return len(c.checkRoleClaim(role)) > 0
}

// IsGrantedRoleInOrganization 通过检查 organizationID 是否位于
// `urn:zitadel:iam:org:project:roles` 声明中所请求角色对应的列表内，
// 实现了 [authorization.Ctx]。
func (c *IntrospectionContext) IsGrantedRoleInOrganization(role, organizationID string) bool {
	if c == nil {
		return false
	}
	_, ok := c.checkRoleClaim(role)[organizationID]
	return ok
}

// IsGrantedRoleInProject 使用 `urn:zitadel:iam:org:project:{projectId}:roles`
// 声明格式，检查该角色是否在指定项目中被授予。
// 按照 Zitadel 最新的标准，这是推荐的格式。
func (c *IntrospectionContext) IsGrantedRoleInProject(projectID, role, organisationID string) bool {
	if c == nil {
		return false
	}
	organisations := c.checkProjectRoleClaim(projectID, role, organisationID)
	return len(organisations) > 0
}

func (c *IntrospectionContext) SetToken(token string) {
	c.token = token
}

func (c *IntrospectionContext) GetToken() string {
	return c.token
}

func (c *IntrospectionContext) checkRoleClaim(role string) map[string]interface{} {
	roles, ok := c.Claims["urn:zitadel:iam:org:project:roles"].(map[string]interface{})
	if !ok || len(roles) == 0 {
		return nil
	}
	organisations, ok := roles[role].(map[string]interface{})
	if !ok {
		return nil
	}
	return organisations
}

func (c *IntrospectionContext) checkProjectRoleClaim(projectID, role, organisationID string) map[string]interface{} {
	claimKey := "urn:zitadel:iam:org:project:" + projectID + ":roles"
	roles, ok := c.Claims[claimKey].(map[string]interface{})
	if !ok || len(roles) == 0 {
		return nil
	}
	organisations, ok := roles[role].(map[string]interface{})
	if !ok {
		return nil
	}
	if organisationID != "" {
		_, ok := organisations[organisationID]
		if !ok {
			return nil
		}
	}
	return organisations
}
