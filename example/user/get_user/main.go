package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	domain  = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	keyPath = flag.String("key", "", "path to your service user's key.json; 为空时回退到环境变量 ZITADEL_KEY_PATH")
	userID  = flag.String("userID", "", "userID of the user to read (required)")
)

// getUser 通过 User API v2 读取单个用户的完整信息（含档案、邮箱等）
func getUser(ctx context.Context, client pb.UserServiceClient, userID string) (*pb.User, error) {
	if userID == "" {
		return nil, errors.New("缺少必填参数: userID")
	}
	resp, err := client.GetUserByID(ctx, &pb.GetUserByIDRequest{UserId: userID})
	if err != nil {
		return nil, fmt.Errorf("查询用户失败: %w", err)
	}
	return resp.GetUser(), nil
}

// resolveKeyPath 读取服务用户密钥文件路径：-key 优先，未设置时回退到环境变量 ZITADEL_KEY_PATH
func resolveKeyPath() string {
	if *keyPath != "" {
		return *keyPath
	}
	return os.Getenv("ZITADEL_KEY_PATH")
}

// 该示例演示如何通过 User API v2 查询单个用户。
// 运行示例：
//
//	go run example/user/get_user \
//	  -domain <instance>.zitadel.cloud \
//	  -key path/to/jwt-key.json \
//	  -userID <userID>
//
// 密钥文件路径也可以通过环境变量 ZITADEL_KEY_PATH 提供（-key 优先级更高）。
func main() {
	flag.Parse()

	ctx := context.Background()

	// 通过实例域名创建聚合客户端：认证（HTTP）与 API（gRPC）地址都由该域名派生。
	// 认证使用服务用户的 key.json（JWT Profile），作用域需包含 ZITADEL 的项目 ID。
	api, err := client.New(ctx, zitadel.New(*domain),
		client.WithAuth(client.DefaultServiceUserAuthentication(resolveKeyPath(), oidc.ScopeOpenID, client.ScopeZitadelAPI())),
	)
	if err != nil {
		log.Fatalln("could not create client", err)
	}
	defer func() {
		if err := api.Close(); err != nil {
			log.Println("could not close client", err)
		}
	}()

	user, err := getUser(ctx, api.UserServiceV2(), *userID)
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
