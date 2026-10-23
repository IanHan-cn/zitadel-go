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
	userID  = flag.String("userID", "", "userID of the user to delete (required)")
	confirm = flag.Bool("confirm", false, "真正执行删除；不提供时只预览待删除的用户")
)

// deleteResult 描述一次删除调用的结果
type deleteResult struct {
	// Preview 为未确认删除时读取到的待删除用户
	Preview *pb.User
	// Deleted 表示是否真的发起了删除请求
	Deleted bool
}

// deleteUser 删除指定用户。
// confirm 为 false 时只读取并返回待删除用户，不会发起删除，避免误操作。
func deleteUser(ctx context.Context, client pb.UserServiceClient, userID string, confirm bool) (deleteResult, error) {
	if userID == "" {
		return deleteResult{}, errors.New("缺少必填参数: userID")
	}
	if !confirm {
		resp, err := client.GetUserByID(ctx, &pb.GetUserByIDRequest{UserId: userID})
		if err != nil {
			return deleteResult{}, fmt.Errorf("预览用户失败: %w", err)
		}
		return deleteResult{Preview: resp.GetUser()}, nil
	}
	if _, err := client.DeleteUser(ctx, &pb.DeleteUserRequest{UserId: userID}); err != nil {
		return deleteResult{}, fmt.Errorf("删除用户失败: %w", err)
	}
	return deleteResult{Deleted: true}, nil
}

// resolveKeyPath 读取服务用户密钥文件路径：-key 优先，未设置时回退到环境变量 ZITADEL_KEY_PATH
func resolveKeyPath() string {
	if *keyPath != "" {
		return *keyPath
	}
	return os.Getenv("ZITADEL_KEY_PATH")
}

// 该示例演示如何通过 User API v2 删除用户。
// 出于安全考虑：不加 -confirm 时只会预览待删除的用户，不会真的删除。
// 运行示例：
//
//	go run example/user/delete_user \
//	  -domain <instance>.zitadel.cloud \
//	  -key path/to/jwt-key.json \
//	  -userID <userID> \
//	  -confirm
//
// 密钥文件路径也可以通过环境变量 ZITADEL_KEY_PATH 提供（-key 优先级更高）。
//
// DeleteUser 是软删除：用户状态变为 deleted、无法再登录，数据仍保留；
// 若只是要临时禁用，请改用 DeactivateUser。
// 调用该 API 需要具备 user.write 权限。
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

	result, err := deleteUser(ctx, api.UserServiceV2(), *userID, *confirm)
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	if !result.Deleted {
		log.Printf("dry run: user %s (%s) would be deleted, add -confirm to execute",
			result.Preview.GetUserId(),
			result.Preview.GetUsername(),
		)
		return
	}
	log.Printf("user %s deleted", *userID)
}
