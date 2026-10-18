package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// 运行示例服务器时需要提供的命令行参数
	domain  = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	keyPath = flag.String("key", "", "path to your key.json")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	// 通过至少提供 zitadel 配置来初始化 API 客户端。
	// 你也可以通过传入已下载的服务用户密钥，
	// 直接设置授权选项，即提供其认证机制：
	api, err := client.New(ctx, zitadel.New(*domain),
		client.WithAuth(client.DefaultServiceUserAuthentication(*keyPath, oidc.ScopeOpenID, client.ScopeZitadelAPI())),
	)
	if err != nil {
		slog.Error("cannot create api client", "error", err)
		os.Exit(1)
	}

	// 本例中我们仅使用 ManagementService 来获取用户所属的组织，
	// 但你同样可以用这套 API 访问所有其他服务（Admin、Auth、User、Session 等）。
	resp, err := api.ManagementService().GetMyOrg(ctx, &management.GetMyOrgRequest{})
	if err != nil {
		slog.Error("cannot retrieve the organisation", "error", err)
		os.Exit(1)
	}
	slog.Info("retrieved the organisation", "orgID", resp.GetOrg().GetId(), "name", resp.GetOrg().GetName())
}
