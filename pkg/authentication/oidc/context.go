package oidc

import (
	"reflect"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// UserInfoContext 以 [oidc.UserInfo] 作为底层数据，实现了
// [authentication.Ctx]（也即 [Ctx]）接口。
type UserInfoContext[C oidc.IDClaims, S rp.SubjectGetter] struct {
	UserInfo S
	Tokens   *oidc.Tokens[C]
}

func (c *UserInfoContext[C, S]) New() Ctx[C, S] {
	return &UserInfoContext[C, S]{}
}

// IsAuthenticated 通过检查 [oidc.UserInfo] 的 `sub` 声明
// 以及 [oidc.Tokens] 中 ID 令牌的 `exp` 声明，来实现 [authentication.Ctx]。
func (c *UserInfoContext[C, S]) IsAuthenticated() bool {
	if c == nil {
		return false
	}
	if exp := c.GetExpiration(); !exp.IsZero() && !time.Now().Before(exp) {
		return false
	}
	return c.UserInfo.GetSubject() != ""
}

// GetExpiration 返回 [oidc.Tokens] 中 ID 令牌的 `exp` 声明。若不存在，则返回零值。
func (c *UserInfoContext[C, S]) GetExpiration() time.Time {
	if c == nil || c.Tokens == nil || isNilClaims(c.Tokens.IDTokenClaims) {
		return time.Time{}
	}
	return c.Tokens.IDTokenClaims.GetExpiration()
}

// isNilClaims 判断 claims 是否为 nil 指针/接口。之所以需要这个函数，
// 是因为 claims 是泛型类型参数，直接写 `claims == nil` 无法通过编译，
// 而比较装箱后的 `any(claims) != nil` 又无法识别带有具体类型的 nil 指针。
func isNilClaims[C oidc.IDClaims](claims C) bool {
	v := reflect.ValueOf(claims)
	if !v.IsValid() {
		// claims 是一个 nil 接口值（例如 C 被实例化为
		// oidc.IDClaims 接口本身，而非某个具体的指针类型）。
		return true
	}
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// SetTokens 实现 [Ctx]
func (c *UserInfoContext[C, S]) SetTokens(tokens *oidc.Tokens[C]) {
	c.Tokens = tokens
}

// GetTokens 实现 [Ctx]
func (c *UserInfoContext[C, S]) GetTokens() *oidc.Tokens[C] {
	return c.Tokens
}

// SetUserInfo 实现 [Ctx]
func (c *UserInfoContext[C, S]) SetUserInfo(info S) {
	c.UserInfo = info
}

// GetUserInfo 实现 [Ctx]
func (c *UserInfoContext[C, S]) GetUserInfo() S {
	return c.UserInfo
}
