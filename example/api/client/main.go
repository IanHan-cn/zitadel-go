package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/auth"
	"github.com/zitadel/zitadel-go/v3/pkg/http/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// 运行示例服务器时需要提供的命令行参数
	domain = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	key    = flag.String("key", "", "path to your api key.json")
	port   = flag.String("port", "8089", "port to run the server on (default is 8089)")
)

/*
 本示例演示如何使用提供的授权（AuthZ）中间件，
 结合 ZITADEL API 一起，借助 ZITADEL 来保护一个 HTTP API。

 它会对外提供以下 2 个不同的端点：
 （这些端点旨在演示各种可能性，并未遵循 REST 最佳实践）：

 - /api/healthz（任何人都可以调用）
 - /api/permissions（需要授权）
*/

func main() {
	flag.Parse()

	ctx := context.Background()

	// 通过提供域名来初始化 zitadel sdk；
	// 并且由于本例聚焦于授权（使用 OAuth2 Introspection），
	// 你还需要用已下载的 api key.json 来完成初始化

	conf := zitadel.New(*domain)
	authZ, err := authorization.New(ctx, conf, oauth.DefaultAuthorization(*key))
	if err != nil {
		slog.Error("zitadel sdk could not initialize authorization", "error", err)
		os.Exit(1)
	}
	// 通过提供 sdk 来初始化 HTTP 中间件
	mw := middleware.New(authZ)

	// 由于我们还要调用 ZITADEL API，因此需要初始化客户端
	c, err := client.New(ctx, conf)
	if err != nil {
		slog.Error("zitadel sdk could not initialize authorization", "error", err)
		os.Exit(1)
	}

	router := http.NewServeMux()

	// 该端点任何人都可以访问，它始终返回 "200 OK" 以表明 API 正在运行
	router.Handle("/api/healthz", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			err = jsonResponse(w, "OK", http.StatusOK)
			if err != nil {
				slog.Error("error writing response", "error", err)
			}
		}))

	// 该端点仅在持有有效授权（本例中为有效的 access_token / PAT）时才可访问。
	// 它会调用 ZITADEL，额外获取在 ZITADEL 中授予该用户的所有权限并返回。
	router.Handle("/api/permissions", mw.RequireAuthorization()(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// 借助 [middleware.Context] 函数，我们可以获取已授权用户的信息。
			// 本例仅通过提供的方法打印用户 ID，并通过直接访问
			// 带类型的 [*oauth.IntrospectionContext] 的字段来打印用户名。
			authCtx := mw.Context(r.Context())
			slog.Info("user accessed permission check", "id", authCtx.UserID(), "username", authCtx.Username)

			// 我们使用调用方的令牌去 ZITADEL API 上查询权限；
			// 这只有在 ZITADEL 包含于令牌的 audience 中时才有效（例如 PAT 总是满足这一条件）
			resp, err := c.AuthService().ListMyZitadelPermissions(client.AuthorizedUserCtx(r.Context()), &auth.ListMyZitadelPermissionsRequest{})
			if err != nil {
				slog.Error("error listing zitadel permissions", "error", err)
				return
			}

			err = jsonResponse(w, resp.Result, http.StatusOK)
			if err != nil {
				slog.Error("error writing response", "error", err)
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

// jsonResponse 是一个简单的辅助函数，用于返回规范的 JSON 响应
func jsonResponse(w http.ResponseWriter, resp any, status int) error {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
