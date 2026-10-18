package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"

	"github.com/zitadel/zitadel-go/v3/pkg/authentication"
	openid "github.com/zitadel/zitadel-go/v3/pkg/authentication/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// 运行示例服务器时需要提供的命令行参数
	domain      = flag.String("domain", "", "your ZITADEL instance domain (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	key         = flag.String("key", "", "encryption key")
	clientID    = flag.String("clientID", "", "clientID provided by ZITADEL")
	redirectURI = flag.String("redirectURI", "", "redirectURI registered at ZITADEL")
	port        = flag.String("port", "8089", "port to run the server on (default is 8089)")

	//go:embed "templates/*.html"
	templates embed.FS
)

/*
 本示例演示如何使用提供的认证（AuthZ）中间件，
 借助 ZITADEL 为你的应用完成用户认证。

 应用的主端点是 /profile 页面，其中会展示已认证用户的一些信息。

 此外，认证处理器会在 /auth 路径前缀下注册若干路由，
 以便将用户重定向到登录界面完成认证后再跳回，同时也用于处理登出。
*/

func main() {
	flag.Parse()

	ctx := context.Background()

	t, err := template.New("").ParseFS(templates, "templates/*.html")
	if err != nil {
		slog.Error("unable to parse template", "error", err)
		os.Exit(1)
	}

	// 通过提供 zitadel 配置和处理器来初始化认证能力。
	// 本例将使用 OIDC/OAuth2 PKCE 流程，因此你还需要用生成的 client_id 来完成初始化：
	authN, err := authentication.New(ctx, zitadel.New(*domain), *key,
		openid.DefaultAuthentication(*clientID, *redirectURI, *key),
	)
	if err != nil {
		slog.Error("zitadel sdk could not initialize", "error", err)
		os.Exit(1)
	}

	// 通过提供 sdk 来初始化中间件
	mw := authentication.Middleware(authN)

	router := http.NewServeMux()

	// 将认证处理器注册到你期望的路径上。
	// 它会在该路径下注册以下处理器：
	// - /login（启动到登录界面的认证流程）
	// - /callback（处理从登录界面回跳的请求）
	// - /logout（处理登出流程）
	router.Handle("/auth/", authN)
	// 该端点仅在通过有效认证后才可访问。若未认证，它会直接将用户
	// 重定向到登录界面进行认证。若认证成功（或此前已认证），用户将看到个人资料页。
	router.Handle("/profile", mw.RequireAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 借助 [middleware.Context] 函数，我们可以获取已认证用户的信息。
		// 本例仅打印带类型的 [*oidc.UserInfoContext] 中 UserInfo 的 JSON 表示。
		authCtx := mw.Context(req.Context())
		data, err := json.MarshalIndent(authCtx.UserInfo, "", "	")
		if err != nil {
			slog.Error("error marshalling profile response", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = t.ExecuteTemplate(w, "profile.html", string(data))
		if err != nil {
			slog.Error("error writing profile response", "error", err)
		}
	})))
	// 该端点任何人都可以访问，但它会检查当前是否已存在有效会话（认证状态）。
	// 若存在活跃会话，相关信息会被放入上下文中，以便后续取用。
	router.Handle("/", mw.CheckAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 这里我们检查是否存在活跃会话，并直接将用户重定向到个人资料页。
		// 你当然也可以使用 [middleware.Context] 获取更多信息并用在首页上。
		if authentication.IsAuthenticated(req.Context()) {
			http.Redirect(w, req, "/profile", http.StatusFound)
			return
		}
		err = t.ExecuteTemplate(w, "home.html", nil)
		if err != nil {
			slog.Error("error writing home page response", "error", err)
		}
	})))

	// 在指定端口上启动服务器（默认为 http://localhost:8089）
	lis := fmt.Sprintf(":%s", *port)
	slog.Info("server listening, press ctrl+c to stop", "addr", "http://localhost"+lis)
	err = http.ListenAndServe(lis, router)
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
