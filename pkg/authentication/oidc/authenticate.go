package oidc

import (
	"context"
	"net/http"
	"net/url"

	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

type DefaultContext = UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo]

type Ctx[C oidc.IDClaims, S rp.SubjectGetter] interface {
	authentication.Ctx
	New() Ctx[C, S]
	SetTokens(*oidc.Tokens[C])
	GetTokens() *oidc.Tokens[C]
	SetUserInfo(S)
	GetUserInfo() S
}

// codeFlowAuthentication 基于 OIDC/OAuth2 授权码流程
// 提供了 [authentication.Handler] 的实现。
// 具体实现请使用 [WithCodeFlow]。
type codeFlowAuthentication[T Ctx[C, S], C oidc.IDClaims, S rp.SubjectGetter] struct {
	relyingParty rp.RelyingParty
}

// WithCodeFlow 创建 [authentication.Handler] 接口的 OIDC/OAuth2 授权码流程实现。
// 令牌端点本身要求客户端提供某种 [ClientAuthentication] 认证方式。
// 可选的实现有 [PKCEAuthentication] 和 [ClientIDSecretAuthentication]。
func WithCodeFlow[T Ctx[C, S], C oidc.IDClaims, S rp.SubjectGetter](auth ClientAuthentication) authentication.HandlerInitializer[T] {
	return func(ctx context.Context, zitadel *zitadel.Zitadel) (authentication.Handler[T], error) {
		relyingParty, err := auth(ctx, zitadel.Origin())
		if err != nil {
			return nil, err
		}
		return &codeFlowAuthentication[T, C, S]{
			relyingParty: relyingParty,
		}, nil
	}
}

type ClientAuthentication func(ctx context.Context, domain string) (rp.RelyingParty, error)

// PKCEAuthentication 允许使用 Proof Key of Code Exchange（PKCE）对换取令牌的请求进行认证。
func PKCEAuthentication(clientID, redirectURI string, scopes []string, cookieHandler *httphelper.CookieHandler) ClientAuthentication {
	return func(ctx context.Context, domain string) (rp.RelyingParty, error) {
		return newRP(ctx, domain, clientID, "", redirectURI, scopes, rp.WithPKCE(cookieHandler))
	}
}

// ClientIDSecretAuthentication 允许使用 ZITADEL 提供的 client_id 和 client_secret 对换取令牌的请求进行认证。
func ClientIDSecretAuthentication(clientID, clientSecret, redirectURI string, scopes []string, cookieHandler *httphelper.CookieHandler) ClientAuthentication {
	return func(ctx context.Context, domain string) (rp.RelyingParty, error) {
		return newRP(ctx, domain, clientID, clientSecret, redirectURI, scopes, rp.WithCookieHandler(cookieHandler))
	}
}

// DefaultAuthentication 是 [WithCodeFlow[*UserInfoContext[*oidc.IDTokenClaims, *oidc.UserInfo], *oidc.IDTokenClaims, *oidc.UserInfo]]
// 的简化版本，只需提供 client_id、redirectURI、encryptionKey 以及可选的 scopes。
// 若未提供 scopes，则默认使用 `"openid", "profile", "email"`。
func DefaultAuthentication(clientID, redirectURI string, key string, scopes ...string) authentication.HandlerInitializer[*DefaultContext] {
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}
	}
	return WithCodeFlow[*DefaultContext, *oidc.IDTokenClaims, *oidc.UserInfo](
		PKCEAuthentication(clientID, redirectURI, scopes, httphelper.NewCookieHandler([]byte(key), []byte(key))),
	)
}

func newRP(ctx context.Context, domain, clientID, clientSecret, redirectURI string, scopes []string, options ...rp.Option) (rp.RelyingParty, error) {
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID}
	}
	return rp.NewRelyingPartyOIDC(ctx, domain, clientID, clientSecret, redirectURI, scopes, options...)
}

// Authenticate 启动 OIDC/OAuth2 授权码流程，并将用户重定向到登录界面。
func (c *codeFlowAuthentication[T, C, S]) Authenticate(w http.ResponseWriter, r *http.Request, state string) {
	rp.AuthURLHandler(func() string { return state }, c.relyingParty)(w, r)
}

// Callback 处理从登录界面回跳的请求，并用授权码换取令牌。
// 此外，它还会从 userinfo_endpoint 获取信息，并将全部内容存入 [Ctx]。
func (c *codeFlowAuthentication[T, C, S]) Callback(w http.ResponseWriter, r *http.Request) (authCtx T, state string) {
	rp.CodeExchangeHandler[C](rp.UserinfoCallback[C, S](func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[C], callbackState string, provider rp.RelyingParty, info S) {
		state = callbackState
		authCtx = authCtx.New().(T)
		authCtx.SetTokens(tokens)
		authCtx.SetUserInfo(info)
	}), c.relyingParty)(w, r)
	return authCtx, state
}

// Logout 会调用（即重定向到）授权服务器（登录界面）上的 end_session_endpoint。
func (c *codeFlowAuthentication[T, C, S]) Logout(w http.ResponseWriter, r *http.Request, authCtx T, state, optionalRedirectURI string) {
	// OIDC 库当前发起的是服务端 POST 请求，但规范要求由浏览器发起调用，
	// 尤其是 ZITADEL 需要存在 "user agent" Cookie 才能终止会话。
	//
	// 该库的现有实现是在规范仍处于草案阶段时完成的，
	// 此后规范已新增更多参数并正式发布。
	// 在该库更新到最新标准之前，我们在此以重定向的方式
	// 实现该库当前的请求（参数保持一致）。
	req := oidc.EndSessionRequest{
		IdTokenHint:           authCtx.GetTokens().IDToken,
		ClientID:              c.relyingParty.OAuthConfig().ClientID,
		PostLogoutRedirectURI: optionalRedirectURI,
		State:                 state,
	}
	endSession, err := url.Parse(c.relyingParty.GetEndSessionEndpoint())
	if err != nil {
		http.Error(w, "failed to build end session endpoint: "+err.Error(), http.StatusInternalServerError)
		return
	}
	params, err := httphelper.URLEncodeParams(req, client.Encoder)
	if err != nil {
		http.Error(w, "failed to build end session parameters: "+err.Error(), http.StatusInternalServerError)
		return
	}
	endSession.RawQuery = params.Encode()
	http.Redirect(w, r, endSession.String(), http.StatusFound)
}
