package authentication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/crypto"

	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	ErrNoCookie  = errors.New("no cookie")
	ErrNoSession = errors.New("no session")
)

// AuthenticationChecker 定义了用于检查认证状态的接口。
// 该接口便于在测试中通过 mock 替换实现。
type AuthenticationChecker[T Ctx] interface {
	IsAuthenticated(req *http.Request) (T, error)
	Authenticate(w http.ResponseWriter, r *http.Request, requestedURI string)
}

// Authenticator 提供认证相关的处理能力，包括检查已有会话、
// 通过将用户重定向到登录界面来发起新的认证等。
type Authenticator[T Ctx] struct {
	authN                 Handler[T]
	logger                *slog.Logger
	router                *http.ServeMux
	sessions              Sessions[T]
	encryptionKey         string
	sessionCookieName     string
	externalSecure        bool
	useCookieSession      bool
	postLogoutRedirectURI string
	onAuthenticated       OnAuthenticatedFunc[T]
}

// 编译期检查，确保 Authenticator 实现了 AuthenticationChecker
var _ AuthenticationChecker[Ctx] = (*Authenticator[Ctx])(nil)

// Option 用于对 [Authenticator] 进行定制，例如日志等。
type Option[T Ctx] func(authorizer *Authenticator[T])

// WithLogger 允许使用 slog.Default() 之外的日志记录器。
func WithLogger[T Ctx](logger *slog.Logger) Option[T] {
	return func(a *Authenticator[T]) {
		a.logger = logger
	}
}

// WithCookieSession 启用无状态会话处理：整个上下文（包括令牌）
// 会被加密后存放在会话 Cookie 中。
// 这样可以免去服务端会话存储，但会增大 Cookie 的体积。
func WithCookieSession[T Ctx]() Option[T] {
	return func(a *Authenticator[T]) {
		a.useCookieSession = true
	}
}

// WithSessionStore 允许使用 [InMemorySessions] 之外的会话存储。
func WithSessionStore[T Ctx](sessions Sessions[T]) Option[T] {
	return func(a *Authenticator[T]) {
		a.sessions = sessions
	}
}

// WithSessionCookieName 允许使用 "zitadel.session" 之外的会话 Cookie 名称。
func WithSessionCookieName[T Ctx](cookieName string) Option[T] {
	return func(a *Authenticator[T]) {
		a.sessionCookieName = cookieName
	}
}

// WithExternalSecure 允许在服务位于反向代理之后时使用 https 重定向。
func WithExternalSecure[T Ctx](externalSecure bool) Option[T] {
	return func(a *Authenticator[T]) {
		a.externalSecure = externalSecure
	}
}

// WithPostLogoutRedirectURI 允许指定用户成功登出后被重定向到的 URL。
func WithPostLogoutRedirectURI[T Ctx](uri string) Option[T] {
	return func(a *Authenticator[T]) {
		a.postLogoutRedirectURI = uri
	}
}

// OnAuthenticatedFunc 在 OIDC 回调成功后、
// 会话被保存且用户被重定向之前调用。
type OnAuthenticatedFunc[T Ctx] func(ctx context.Context, authCtx T) error

// WithOnAuthenticated 注册一个钩子，在回调中认证成功后被调用。
// 如果该钩子返回错误，登录流程将中止并返回 500 状态码。
func WithOnAuthenticated[T Ctx](fn OnAuthenticatedFunc[T]) Option[T] {
	return func(a *Authenticator[T]) {
		a.onAuthenticated = fn
	}
}

func New[T Ctx](ctx context.Context, zitadel *zitadel.Zitadel, encryptionKey string, initAuthentication HandlerInitializer[T], options ...Option[T]) (*Authenticator[T], error) {
	authN, err := initAuthentication(ctx, zitadel)
	if err != nil {
		return nil, err
	}
	authenticator := &Authenticator[T]{
		authN:             authN,
		sessions:          NewInMemorySessions[T](),
		encryptionKey:     encryptionKey,
		sessionCookieName: "zitadel.session",
		logger:            slog.Default(),
	}
	for _, option := range options {
		option(authenticator)
	}
	authenticator.createRouter()
	return authenticator, nil
}

// ServeHTTP 为认证处理器及其三个子路由提供服务。
func (a *Authenticator[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.StripPrefix("/auth", a.router).ServeHTTP(w, r)
}

// Authenticate 发起一次新的认证（通过将用户重定向到登录界面）。
// 应用中最初请求的 URI 会作为加密后的 state 传递。
func (a *Authenticator[T]) Authenticate(w http.ResponseWriter, r *http.Request, requestedURI string) {
	s := &State{RequestedURI: requestedURI}
	stateParam, err := s.Encrypt(a.encryptionKey)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.authN.Authenticate(w, r, stateParam)
}

// Callback 处理从登录界面回跳的请求。认证成功时会创建一个新会话，
// 并将其 ID 存入 Cookie。
// 用户将被重定向到最初请求的界面（作为加密 state 传入）
func (a *Authenticator[T]) Callback(w http.ResponseWriter, req *http.Request) {
	authCtx, stateParam := a.authN.Callback(w, req)
	if !authCtx.IsAuthenticated() {
		a.logger.Error("unauthenticated after callback")
		http.Error(w, "not authenticated", http.StatusForbidden)
		return
	}
	state, err := DecryptState(stateParam, a.encryptionKey)
	if err != nil {
		a.logger.Error("unable to decrypt state", "state", stateParam)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if a.onAuthenticated != nil {
		if err := a.onAuthenticated(req.Context(), authCtx); err != nil {
			a.logger.Error("on authenticated hook failed", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	redirectURI := state.RequestedURI
	if redirectURI == "" {
		redirectURI = "/"
	}

	var maxAge int
	if expAuthCtx, ok := any(authCtx).(interface{ GetExpiration() time.Time }); ok {
		if exp := expAuthCtx.GetExpiration(); !exp.IsZero() {
			// 避免向下取整为 0，否则会退化成浏览器会话级别的 Cookie
			maxAge = max(int(time.Until(exp).Seconds()), 1)
		}
	}

	if a.useCookieSession {
		// 无状态模式：将整个上下文序列化并加密后写入 Cookie。
		data, err := json.Marshal(authCtx)
		if err != nil {
			a.logger.Error("unable to serialize auth context", "error", err)
			http.Error(w, "unable to serialize auth context", http.StatusInternalServerError)
			return
		}
		if err = a.setSessionCookie(w, string(data), maxAge); err != nil {
			a.logger.Error("unable to save session cookie", "error", err)
			http.Error(w, "session could not be stored", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, redirectURI, http.StatusFound)
		return
	}

	// 原有有状态模式：将会话保存在内存中。
	id := uuid.NewString()
	if err = a.sessions.Set(id, authCtx); err != nil {
		a.logger.Error("unable to save session", "error", err, "id", id)
		http.Error(w, "session could not be stored", http.StatusInternalServerError)
		return
	}
	if err = a.setSessionCookie(w, id, maxAge); err != nil {
		a.logger.Error("unable to save session cookie", "error", err, "id", id)
		http.Error(w, "session could not be stored", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, req, redirectURI, http.StatusFound)
}

// Logout 会终止当前已有的会话。
func (a *Authenticator[T]) Logout(w http.ResponseWriter, req *http.Request) {
	authCtx, err := a.IsAuthenticated(req)
	if err != nil {
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}

	s := &State{RequestedURI: ""}
	stateParam, err := s.Encrypt(a.encryptionKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.deleteSessionCookie(w)

	postLogout := a.postLogoutRedirectURI
	if postLogout == "" {
		// 若未设置自定义 URI，则沿用原有的默认逻辑
		proto := "http"
		if req.TLS != nil || a.externalSecure {
			proto = "https"
		}
		postLogout = fmt.Sprintf("%s://%s/", proto, req.Host)
	}

	a.authN.Logout(w, req, authCtx, stateParam, postLogout)
}

// IsAuthenticated 检查当前是否已存在会话。
// 若存在，则将其返回。
func (a *Authenticator[T]) IsAuthenticated(req *http.Request) (T, error) {
	var t T
	cookie, err := req.Cookie(a.sessionCookieName)
	if err != nil {
		return t, ErrNoCookie
	}
	sessionValue, err := crypto.DecryptAES(cookie.Value, a.encryptionKey)
	if err != nil {
		a.logger.Log(req.Context(), slog.LevelWarn, "unable to decrypt session cookie")
		return t, ErrNoSession
	}

	if a.useCookieSession {
		// 无状态模式：直接从 Cookie 中反序列化上下文。
		if err = json.Unmarshal([]byte(sessionValue), &t); err != nil {
			a.logger.Log(req.Context(), slog.LevelWarn, "unable to deserialize auth context from cookie")
			return t, ErrNoSession
		}
		if !t.IsAuthenticated() {
			a.logger.Log(req.Context(), slog.LevelWarn, "session is no longer authenticated")
			var invalid T
			return invalid, ErrNoSession
		}
		return t, nil
	}

	// 原有有状态模式：将解密后的值作为会话 ID 在存储中查找。
	session, err := a.sessions.Get(sessionValue)
	if err != nil {
		a.logger.Log(req.Context(), slog.LevelWarn, "no session found for cookie", "sessionID", sessionValue)
		return t, ErrNoSession
	}
	if !session.IsAuthenticated() {
		a.logger.Log(req.Context(), slog.LevelWarn, "session is no longer authenticated", "sessionID", sessionValue)
		var invalid T
		return invalid, ErrNoSession
	}
	return session, nil
}

func (a *Authenticator[T]) createRouter() {
	a.router = http.NewServeMux()
	a.router.Handle("/login", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.Authenticate(w, req, "")
	}))
	a.router.Handle("/callback", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.Callback(w, req)
	}))
	a.router.Handle("/logout", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.Logout(w, req)
	}))
}

func (a *Authenticator[T]) setSessionCookie(w http.ResponseWriter, sessionID string, maxAge int) error {
	value, err := crypto.EncryptAES(sessionID, a.encryptionKey)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookieName,
		Value:    value,
		Path:     "/",
		Domain:   "",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (a *Authenticator[T]) deleteSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookieName,
		Path:     "/",
		Domain:   "",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Handler 定义了认证与登出的处理方式
type Handler[T Ctx] interface {
	Authenticate(w http.ResponseWriter, r *http.Request, state string)
	Callback(w http.ResponseWriter, r *http.Request) (t T, state string)
	Logout(w http.ResponseWriter, r *http.Request, authCtx T, state, optionalRedirectURI string)
}

// HandlerInitializer 抽象了 [Handler] 的初始化过程，提供 ZITADEL 域名、端口以及是否启用 tls
type HandlerInitializer[T Ctx] func(ctx context.Context, zitadel *zitadel.Zitadel) (Handler[T], error)
