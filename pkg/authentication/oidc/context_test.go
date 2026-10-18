package oidc_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	zitadeloidc "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
)

type testContext = *zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]

func TestUserInfoContext_IsAuthenticated(t *testing.T) {
	tests := []struct {
		name string
		ctx  testContext
		want bool
	}{
		{
			name: "nil context",
			ctx:  nil,
			want: false,
		},
		{
			name: "no subject",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{},
			},
			want: false,
		},
		{
			name: "subject without tokens",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
			},
			want: true,
		},
		{
			name: "tokens without id token claims",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens:   &oidc.Tokens[*oidc.IDTokenClaims]{IDToken: "id-token"},
			},
			want: true,
		},
		{
			name: "id token without expiration",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
					IDTokenClaims: &oidc.IDTokenClaims{},
				},
			},
			want: true,
		},
		{
			name: "id token not yet expired",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
					IDTokenClaims: &oidc.IDTokenClaims{
						TokenClaims: oidc.TokenClaims{
							Expiration: oidc.FromTime(time.Now().Add(time.Hour)),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "id token expired",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
					IDTokenClaims: &oidc.IDTokenClaims{
						TokenClaims: oidc.TokenClaims{
							Expiration: oidc.FromTime(time.Now().Add(-time.Hour)),
						},
					},
				},
			},
			want: false,
		},
		{
			// 访问令牌的过期时间不应影响会话有效性：只有 ID 令牌的
			// exp 声明才起作用。访问令牌过期后通常会在后台自动刷新，
			// 而不会让底层的身份断言失效。
			name: "access token expired but id token still valid",
			ctx: &zitadeloidc.UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]{
				UserInfo: &oidc.UserInfo{Subject: "user-1"},
				Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
					Token: &oauth2.Token{Expiry: time.Now().Add(-time.Hour)},
					IDTokenClaims: &oidc.IDTokenClaims{
						TokenClaims: oidc.TokenClaims{
							Expiration: oidc.FromTime(time.Now().Add(time.Hour)),
						},
					},
				},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.ctx.IsAuthenticated())
		})
	}
}

// TestUserInfoContext_IsAuthenticated_NilInterfaceClaims 覆盖了将 C 实例化为
// 裸的 oidc.IDClaims 接口（而非具体指针类型）的情况。此时零值的 IDTokenClaims
// 是一个 nil 接口，而不是 nil 指针，reflect.ValueOf 会将其报告为无效的 Value，
// 而非 nil 的 Ptr/Interface Value。
func TestUserInfoContext_IsAuthenticated_NilInterfaceClaims(t *testing.T) {
	ctx := &zitadeloidc.UserInfoContext[oidc.IDClaims, *oidc.UserInfo]{
		UserInfo: &oidc.UserInfo{Subject: "user-1"},
		Tokens:   &oidc.Tokens[oidc.IDClaims]{IDToken: "id-token"},
	}
	assert.True(t, ctx.IsAuthenticated())
}
