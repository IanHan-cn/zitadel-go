package main

import (
	"context"
	"flag"
	"log"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client/auth"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/auth"
)

var (
	issuer = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	api    = flag.String("api", "", "gRPC endpoint of your ZITADEL instance (in the form: <instance>.zitadel.cloud:443 or <yourdomain>:443)")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	//为 auth api 创建一个客户端，需要提供：
	//- issuer（例如 https://acme-dtfhdg.zitadel.cloud）
	//- api（例如 acme-dtfhdg.zitadel.cloud:443）
	//- scopes（需包含 ZITADEL 的项目 ID），
	//- 一个 JWT Profile 令牌来源（例如你的 key json 路径），若未提供，则会从环境变量 ZITADEL_KEY_PATH 设置的路径读取该文件
	client, err := auth.NewClient(
		ctx,
		*issuer,
		*api,
		[]string{oidc.ScopeOpenID, zitadel.ScopeZitadelAPI()},
		zitadel.WithJWTProfileTokenSource(middleware.JWTProfileFromPath(ctx, "key.json")),
	)
	if err != nil {
		log.Fatalln("could not create client", err)
	}
	defer func() {
		err := client.Connection.Close()
		if err != nil {
			log.Println("could not close grpc connection", err)
		}
	}()

	//调用 ZITADEL，打印你的服务用户的名称与创建日期
	//若未发生错误，则说明调用成功
	resp, err := client.GetMyUser(ctx, &pb.GetMyUserRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("%s was created on %s", resp.User.UserName, resp.User.Details.CreationDate.AsTime())
}
