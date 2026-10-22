package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"google.golang.org/grpc"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

var (
	issuer = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	api    = flag.String("api", "", "gRPC endpoint of your ZITADEL instance (in the form: <instance>.zitadel.cloud:443 or <yourdomain>:443)")
	userID = flag.String("userID", "", "userID of the user to read (required)")
)

// userGetter 只暴露本样例需要用到的方法，便于在单元测试中用 fake 替换真实客户端
type userGetter interface {
	GetUserByID(ctx context.Context, in *pb.GetUserByIDRequest, opts ...grpc.CallOption) (*pb.GetUserByIDResponse, error)
}

// getUser 通过 User API v2 读取单个用户的完整信息（含档案、邮箱等）
func getUser(ctx context.Context, client userGetter, userID string) (*pb.User, error) {
	if userID == "" {
		return nil, errors.New("缺少必填参数: userID")
	}
	resp, err := client.GetUserByID(ctx, &pb.GetUserByIDRequest{UserId: userID})
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	return resp.GetUser(), nil
}

// 该示例演示如何通过 User API v2 查询单个用户。
// 运行示例：
//
//	ZITADEL_KEY_PATH=path/to/jwt-key.json go run example/user/get_user \
//	  -issuer https://<instance>.zitadel.cloud \
//	  -api <instance>.zitadel.cloud:443 \
//	  -userID <userID>
//
// 私有化部署时 issuer 为实例外部 HTTPS 地址，api 为 gRPC 地址（主机名:端口，不带 https://）：
//
//	-issuer https://zitadel.corp.example.com -api zitadel.corp.example.com:443
func main() {
	flag.Parse()

	ctx := context.Background()

	// 为 User API v2 创建一个客户端（私有化部署时 api 请填写实例对外暴露 gRPC 的主机名:端口）
	client, err := userv2.NewClient(
		ctx,
		*issuer,
		*api,
		[]string{oidc.ScopeOpenID, zitadel.ScopeZitadelAPI()},
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

	user, err := getUser(ctx, client, *userID)
	if err != nil {
		log.Fatalln("call failed: ", err)
	}

	log.Printf("user: id=%s username=%s state=%s created=%s",
		user.GetUserId(),
		user.GetUsername(),
		user.GetState(),
		user.GetDetails().GetCreationDate().AsTime(),
	)
	log.Printf("profile: givenName=%q familyName=%q nickName=%q displayName=%q preferredLanguage=%q",
		user.GetHuman().GetProfile().GetGivenName(),
		user.GetHuman().GetProfile().GetFamilyName(),
		user.GetHuman().GetProfile().GetNickName(),
		user.GetHuman().GetProfile().GetDisplayName(),
		user.GetHuman().GetProfile().GetPreferredLanguage(),
	)
	log.Printf("email: %s verified=%t", user.GetHuman().GetEmail().GetEmail(), user.GetHuman().GetEmail().GetIsVerified())
	log.Printf("phone: %s verified=%t", user.GetHuman().GetPhone().GetPhone(), user.GetHuman().GetPhone().GetIsVerified())
	log.Printf("login names: %v", user.GetLoginNames())
}
