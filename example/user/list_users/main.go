package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"google.golang.org/grpc"

	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel"
	object "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

var (
	issuer   = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	api      = flag.String("api", "", "gRPC endpoint of your ZITADEL instance (in the form: <instance>.zitadel.cloud:443 or <yourdomain>:443)")
	orgID    = flag.String("orgID", "", "只返回该组织下的用户；为空则返回调用者有权限查看的全部用户")
	username = flag.String("username", "", "按用户名过滤（忽略大小写精确匹配）")
	email    = flag.String("email", "", "按邮箱过滤（忽略大小写精确匹配）")
	limit    = flag.Uint("limit", 100, "单页返回的最大条数")
	offset   = flag.Uint64("offset", 0, "分页偏移量")
)

// userLister 只暴露本样例需要用到的方法，便于在单元测试中用 fake 替换真实客户端
type userLister interface {
	ListUsers(ctx context.Context, in *pb.ListUsersRequest, opts ...grpc.CallOption) (*pb.ListUsersResponse, error)
}

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
func listUsers(ctx context.Context, client userLister, p listUsersParams) (*pb.ListUsersResponse, error) {
	resp, err := client.ListUsers(ctx, buildListUsersRequest(p))
	if err != nil {
		return nil, fmt.Errorf("查询用户列表失败: %w", err)
	}
	return resp, nil
}

// 该示例演示如何通过 User API v2 查询（全部）用户列表。
// 运行示例：
//
//	ZITADEL_KEY_PATH=path/to/jwt-key.json go run example/user/list_users \
//	  -issuer https://<instance>.zitadel.cloud \
//	  -api <instance>.zitadel.cloud:443 \
//	  -orgID <orgID> \
//	  -limit 100
//
// 私有化部署时 issuer 为实例外部 HTTPS 地址，api 为 gRPC 地址（主机名:端口，不带 https://）：
//
//	-issuer https://zitadel.corp.example.com -api zitadel.corp.example.com:443
//
// 需要注意：不传 -orgID 时会返回调用者有权限查看的全部用户；
// 实例用户较多时请配合 -limit/-offset 分页使用。
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

	resp, err := listUsers(ctx, client, listUsersParams{
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
