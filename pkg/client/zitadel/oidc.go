package zitadel

import "fmt"

const (
	scopeFormatProjectID  = "urn:zitadel:iam:org:project:id:%s:aud"
	scopeZITADELProjectID = "zitadel"
)

// ScopeProjectID 会将指定的 projectID 添加到访问令牌和 ID 令牌的 audience 中
// deprecated: 请改用 [client.ScopeProjectID]
func ScopeProjectID(projectID string) string {
	return fmt.Sprintf(scopeFormatProjectID, projectID)
}

// ScopeZitadelAPI 添加 ZITADEL 项目自身的 ProjectID
// deprecated: 请改用 [client.ScopeZitadelAPI]
func ScopeZitadelAPI() string {
	return ScopeProjectID(scopeZITADELProjectID)
}
