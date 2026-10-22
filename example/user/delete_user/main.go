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
	issuer  = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	api     = flag.String("api", "", "gRPC endpoint of your ZITADEL instance (in the form: <instance>.zitadel.cloud:443 or <yourdomain>:443)")
	userID  = flag.String("userID", "", "userID of the user to delete (required)")
	confirm = flag.Bool("confirm", false, "真正执行删除；不提供时只预览待删除的用户")
)

// userDeleter 只暴露本样例需要用到的方法，便于在单元测试中用 fake 替换真实客户端
type userDeleter interface {
	GetUserByID(ctx context.Context, in *pb.GetUserByIDRequest, opts ...grpc.CallOption) (*pb.GetUserByIDResponse, error)
	DeleteUser(ctx context.Context, in *pb.DeleteUserRequest, opts ...grpc.CallOption) (*pb.DeleteUserResponse, error)
}

// deleteResult 描述一次删除调用的结果
type deleteResult struct {
	// Preview 为未确认删除时读取到的待删除用户
	Preview *pb.User
	// Deleted 表示是否真的发起了删除请求
	Deleted bool
}

// deleteUser 删除指定用户。
// confirm 为 false 时只读取并返回待删除用户，不会发起删除，避免误操作。
func deleteUser(ctx context.Context, client userDeleter, userID string, confirm bool) (deleteResult, error) {
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

// 该示例演示如何通过 User API v2 删除用户。
// 出于安全考虑：不加 -confirm 时只会预览待删除的用户，不会真的删除。
// 运行示例：
//
//	ZITADEL_KEY_PATH=path/to/jwt-key.json go run example/user/delete_user \
//	  -issuer https://<instance>.zitadel.cloud \
//	  -api <instance>.zitadel.cloud:443 \
//	  -userID <userID> \
//	  -confirm
//
// 私有化部署时 issuer 为实例外部 HTTPS 地址，api 为 gRPC 地址（主机名:端口，不带 https://）：
//
//	-issuer https://zitadel.corp.example.com -api zitadel.corp.example.com:443
//
// DeleteUser 是软删除：用户状态变为 deleted、无法再登录，数据仍保留；
// 若只是要临时禁用，请改用 DeactivateUser。
// 调用该 API 需要具备 user.write 权限。
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

	result, err := deleteUser(ctx, client, *userID, *confirm)
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
