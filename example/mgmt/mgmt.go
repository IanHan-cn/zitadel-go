package main

import (
	"context"
	"flag"
	"log"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
)

var (
	issuer = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	api    = flag.String("api", "", "gRPC endpoint of your ZITADEL instance (in the form: <instance>.zitadel.cloud:443 or <yourdomain>:443)")
	orgID  = flag.String("orgID", "", "orgID to set for overwrite example")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	//为 management api 创建一个客户端，需要提供：
	//- issuer（例如 https://acme-dtfhdg.zitadel.cloud）
	//- api（例如 acme-dtfhdg.zitadel.cloud:443）
	//- scopes（需包含 ZITADEL 的项目 ID），
	//- 一个 JWT Profile 令牌来源（例如你的 key json 路径），若未提供，则会从环境变量 ZITADEL_KEY_PATH 设置的路径读取该文件
	//- 调用将在其下执行的组织 ID
	//（默认为调用用户所属的资源所有者/组织，也可以针对每次调用单独指定）
	client, err := management.NewClient(
		ctx,
		*issuer,
		*api,
		[]string{oidc.ScopeOpenID, zitadel.ScopeZitadelAPI()},
		//zitadel.WithJWTProfileTokenSource(middleware.JWTProfileFromPath(ctx, "key.json")),
		//zitadel.WithOrgID(*orgID),
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

	//调用 ZITADEL，打印你所在组织的名称与创建日期
	//若未发生错误，则说明调用成功
	resp, err := client.GetMyOrg(ctx, &pb.GetMyOrgRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("%s was created on: %s", resp.Org.Name, resp.Org.Details.CreationDate.AsTime())

	//若某些调用需要切换到其他组织上下文，你可以通过直接设置 orgID 来覆盖它
	//在本例中，只需设置 `orgID` 这个命令行参数即可
	respOverwrite, err := client.GetMyOrg(middleware.SetOrgID(ctx, *orgID), &pb.GetMyOrgRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("%s was created on: %s", respOverwrite.Org.Name, respOverwrite.Org.Details.CreationDate.AsTime())
}
