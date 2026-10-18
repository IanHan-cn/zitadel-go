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
	"strings"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/http/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// 运行示例服务器时需要提供的命令行参数
	domain = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	key    = flag.String("key", "", "path to your key.json")
	port   = flag.String("port", "8089", "port to run the server on (default is 8089)")

	// tasks 用于在内存中保存一个列表，供受保护的端点使用
	tasks []string
)

/*
 本示例演示如何使用提供的授权（AuthZ）中间件，借助 ZITADEL 来保护一个 HTTP API。

 它会对外提供以下 3 个不同的端点：
 （这些端点旨在演示各种可能性，并未遵循 REST 最佳实践）：

 - /api/healthz（任何人都可以调用）
 - /api/tasks（需要授权）
 - /api/add-task（需要授权且已授予 `admin` 角色）
*/

func main() {
	flag.Parse()

	ctx := context.Background()

	// 通过提供 zitadel 配置和校验器来初始化授权能力。
	// 本例将使用 OAuth2 Introspection，因此你还需要提供已下载的 api key.json
	authZ, err := authorization.New(ctx, zitadel.New(*domain), oauth.DefaultAuthorization(*key))
	if err != nil {
		slog.Error("zitadel sdk could not initialize", "error", err)
		os.Exit(1)
	}

	// 通过提供授权能力来初始化 HTTP 中间件
	mw := middleware.New(authZ)

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
	// 它会列出所有已保存的任务。若用户被授予了 `admin` 角色，
	// 还会额外添加一条提示他去新建任务的任务项。
	router.Handle("/api/tasks", mw.RequireAuthorization()(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// 借助 [middleware.Context] 函数，我们可以获取已授权用户的信息。
			// 本例仅通过提供的方法打印用户 ID，并通过直接访问
			// 带类型的 [*oauth.IntrospectionContext] 的字段来打印用户名。
			authCtx := mw.Context(r.Context())
			slog.Info("user accessed task list", "id", authCtx.UserID(), "username", authCtx.Username)

			// 虽然任何已授权用户都可以访问该端点，但你可能会想在
			// 用户被授予某个特定角色时采取额外操作。本例中会提示 `admin` 去新建任务：
			list := tasks
			if authCtx.IsGrantedRole("admin") {
				list = append(list, "create a new task on /api/add-task")
			}

			// 返回已有的任务列表
			err = jsonResponse(w, &taskList{Tasks: list}, http.StatusOK)
			if err != nil {
				slog.Error("error writing response", "error", err)
			}
		})))

	// 该端点仅在持有有效授权且被授予 `admin` 角色（在任意组织内）时才可访问。
	// 它会将传入的任务添加到已有的任务列表中。
	router.Handle("/api/add-task", mw.RequireAuthorization(authorization.WithRole(`admin`))(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// 获取传入的任务，不接受空值
			task := strings.TrimSpace(r.FormValue("task"))
			if task == "" {
				err = jsonResponse(w, "task must not be empty", http.StatusBadRequest)
				if err != nil {
					slog.Error("error writing invalid task response", "error", err)
					return
				}
				return
			}

			// 既然不为空，就把它加入已有的列表
			tasks = append(tasks, task)

			// 由于我们只需要已授权用户的 userID，不需要其他特定数据，因此可以直接使用 [authorization.UserID]
			slog.Info("admin added task", "id", authorization.UserID(r.Context()), "task", task)

			// 告知管理员已成功添加
			err = jsonResponse(w, fmt.Sprintf("task `%s` added", task), http.StatusOK)
			if err != nil {
				slog.Error("error writing task added response", "error", err)
				return
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

type taskList struct {
	Tasks []string `json:"tasks,omitempty"`
}
