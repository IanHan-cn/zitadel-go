package main

import (
	"context"
	"flag"
	"log"

	"github.com/zitadel/zitadel-go/v3/pkg/client/system"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/system"
)

var (
	issuer = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	api    = flag.String("api", "", "gRPC endpoint of your ZITADEL instance (in the form: <instance>.zitadel.cloud:443 or <yourdomain>:443)")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	//为 system api 创建一个客户端，需要提供：
	//- issuer（例如 https://acme-dtfhdg.zitadel.cloud）
	//- api（例如 acme-dtfhdg.zitadel.cloud:443）
	//- 一个 JWT Profile 令牌来源（例如你的 key.pem 路径），以及 ZITADEL 中 `SystemAPIUsers` 配置里对应的 userID
	client, err := system.NewClient(
		ctx,
		*issuer,
		*api,
		system.JWTProfileFromPath("system_user_1.pem", "system_user_1"),
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

	//调用 ZITADEL，打印所有实例的名称与创建日期
	//若未发生错误，则说明调用成功
	//nolint:staticcheck // 为简洁起见，示例中使用了已废弃的调用。
	resp, err := client.ListInstances(ctx, &pb.ListInstancesRequest{})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	//打印所有实例
	for _, instance := range resp.GetResult() {
		log.Printf("%s was created on %s", instance.Name, instance.Details.CreationDate.AsTime())
	}
}
