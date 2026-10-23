package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	object "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

var (
	domain   = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	keyPath  = flag.String("key", "", "path to your service user's key.json; 为空时回退到环境变量 ZITADEL_KEY_PATH")
	orgID    = flag.String("orgID", "", "只返回该组织下的用户；为空则返回调用者有权限查看的全部用户")
	username = flag.String("username", "", "按用户名过滤（忽略大小写精确匹配）")
	email    = flag.String("email", "", "按邮箱过滤（忽略大小写精确匹配）")
	limit    = flag.Uint("limit", 100, "单页返回的最大条数")
	offset   = flag.Uint64("offset", 0, "分页偏移量")
)

// listUsersParams 汇总查询用户列表所需的全部入参
type listUsersParams struct {
	OrgID    string
	Username string
	Email    string
	Limit    uint32
	Offset   uint64
}

// buildListUsersRequest 把入参组装成 ListUsers 请求。
// 过滤条件只追加非空的项，排序以用户名为准，便于结果稳定可预期。
func buildListUsersRequest(p listUsersParams) *pb.ListUsersRequest {
	req := &pb.ListUsersRequest{
		Query: &object.ListQuery{
			Offset: p.Offset,
			Limit:  p.Limit,
			Asc:    true,
		},
		SortingColumn: pb.UserFieldName_USER_FIELD_NAME_USER_NAME,
	}
	// 注意：不指定组织时，ListUsers 会返回调用者有权限查看的**全部**用户，而非仅当前组织
	if p.OrgID != "" {
		req.Queries = append(req.Queries, &pb.SearchQuery{
			Query: &pb.SearchQuery_OrganizationIdQuery{
				OrganizationIdQuery: &pb.OrganizationIdQuery{OrganizationId: p.OrgID},
			},
		})
	}
	if p.Username != "" {
		req.Queries = append(req.Queries, &pb.SearchQuery{
			Query: &pb.SearchQuery_UserNameQuery{
				UserNameQuery: &pb.UserNameQuery{
					UserName: p.Username,
					Method:   object.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE,
				},
			},
		})
	}
	if p.Email != "" {
		req.Queries = append(req.Queries, &pb.SearchQuery{
			Query: &pb.SearchQuery_EmailQuery{
				EmailQuery: &pb.EmailQuery{
					EmailAddress: p.Email,
					Method:       object.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE,
				},
			},
		})
	}
	return req
}

// listUsers 通过 User API v2 查询用户列表
func listUsers(ctx context.Context, client pb.UserServiceClient, p listUsersParams) (*pb.ListUsersResponse, error) {
	resp, err := client.ListUsers(ctx, buildListUsersRequest(p))
	if err != nil {
		return nil, fmt.Errorf("查询用户列表失败: %w", err)
	}
	return resp, nil
}

// resolveKeyPath 读取服务用户密钥文件路径：-key 优先，未设置时回退到环境变量 ZITADEL_KEY_PATH
func resolveKeyPath() string {
	if *keyPath != "" {
		return *keyPath
	}
	return os.Getenv("ZITADEL_KEY_PATH")
}

// 该示例演示如何通过 User API v2 查询（全部）用户列表。
// 运行示例：
//
//	go run example/user/list_users \
//	  -domain <instance>.zitadel.cloud \
//	  -key path/to/jwt-key.json \
//	  -orgID <orgID> \
//	  -limit 100
//
// 密钥文件路径也可以通过环境变量 ZITADEL_KEY_PATH 提供（-key 优先级更高）。
//
// 需要注意：不传 -orgID 时会返回调用者有权限查看的全部用户；
// 实例用户较多时请配合 -limit/-offset 分页使用。
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

	resp, err := listUsers(ctx, api.UserServiceV2(), listUsersParams{
		OrgID:    *orgID,
		Username: *username,
		Email:    *email,
		Limit:    uint32(*limit),
		Offset:   *offset,
	})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}

	log.Printf("total users: %d", resp.GetDetails().GetTotalResult())
	for _, user := range resp.GetResult() {
		log.Printf("user: id=%s username=%s state=%s email=%s loginNames=%v",
			user.GetUserId(),
			user.GetUsername(),
			user.GetState(),
			user.GetHuman().GetEmail().GetEmail(),
			user.GetLoginNames(),
		)
	}
}
