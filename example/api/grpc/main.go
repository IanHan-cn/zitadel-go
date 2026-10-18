package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	v3alpha "github.com/zitadel/zitadel-go/v3/example/api/grpc/proto"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/grpc/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	// 运行示例服务器时需要提供的命令行参数
	domain = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	key    = flag.String("key", "", "path to your key.json")
	port   = flag.String("port", "8089", "port to run the server on (default is 8089)")
)

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

	// 通过提供 sdk 和授权检查项来初始化 GRPC 中间件
	mw := middleware.New(authZ, checks)

	// 创建 GRPC 服务器并配置所需的拦截器
	serverOptions := []grpc.ServerOption{
		grpc.UnaryInterceptor(mw.Unary()),
		grpc.StreamInterceptor(mw.Stream()),
	}
	grpcServer := grpc.NewServer(serverOptions...)

	// 注册你自己的服务端实现
	v3alpha.RegisterExampleServiceServer(grpcServer, NewServer(mw))
	// 为方便使用，我们还注册了 grpc server reflection
	reflection.Register(grpcServer)

	// 最后在 8099 端口上启动服务器
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", *port))
	if err != nil {
		slog.Error("creating listener failed", "error", err)
		os.Exit(1)
	}
	err = grpcServer.Serve(lis)
	if err != nil {
		slog.Error("server terminated", "error", err)
		os.Exit(1)
	}
}
