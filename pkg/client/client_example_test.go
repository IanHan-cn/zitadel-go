package client_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

// ExampleClient_GetValidToken 演示了如何从客户端获取有效的访问令牌，
// 以便对 SDK 未覆盖的接口发起自定义 API 调用。
func ExampleClient_GetValidToken() {
	ctx := context.Background()

	// 创建一个使用 JWT profile 认证的客户端
	authOption := client.DefaultServiceUserAuthentication(
		"path/to/key.json",
		oidc.ScopeOpenID,
		client.ScopeZitadelAPI(),
	)

	api, err := client.New(ctx, zitadel.New("example.zitadel.cloud"), client.WithAuth(authOption))
	if err != nil {
		log.Fatal(err)
	}
	defer api.Close()

	// 获取一个有效令牌，用于自定义 API 调用
	token, err := api.GetValidToken()
	if err != nil {
		log.Fatal(err)
	}

	// 使用该令牌向 SDK 未覆盖的
	// ZITADEL 端点发起自定义 HTTP 请求
	req, _ := http.NewRequest("GET", "https://example.zitadel.cloud/custom/endpoint", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// 若令牌已过期，SDK 会自动刷新它
	fmt.Printf("Token retrieved successfully (length: %d)\n", len(token))
}
