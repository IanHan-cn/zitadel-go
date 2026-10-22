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
	issuer            = flag.String("issuer", "", "issuer of your ZITADEL instance (in the form: https://<instance>.zitadel.cloud or https://<yourdomain>)")
	api               = flag.String("api", "", "gRPC endpoint of your ZITADEL instance (in the form: <instance>.zitadel.cloud:443 or <yourdomain>:443)")
	orgID             = flag.String("orgID", "", "orgID of the organization the user is created in (required)")
	username          = flag.String("username", "", "username of the new user; defaults to the email if empty")
	preferredLanguage = flag.String("preferredLanguage", "", "preferred language of the new user; defaults to en if empty")
	givenName         = flag.String("givenName", "", "given (first) name of the new user")
	familyName        = flag.String("familyName", "", "family (last) name of the new user")
	email             = flag.String("email", "", "email of the new user (required)")
	password          = flag.String("password", "", "initial password; if empty no password is set and the user is initialized by email")
	changeRequired    = flag.Bool("changeRequired", true, "require the user to change the password on the first login")
	verified          = flag.Bool("verified", false, "mark the email as verified; if false a verification email is sent")
)

// userCreator 只暴露本样例需要用到的方法，便于在单元测试中用 fake 替换真实客户端
type userCreator interface {
	CreateUser(ctx context.Context, in *pb.CreateUserRequest, opts ...grpc.CallOption) (*pb.CreateUserResponse, error)
}

// createUserParams 汇总创建普通用户所需的全部入参
type createUserParams struct {
	OrgID             string
	Username          string
	PreferredLanguage string
	GivenName         string
	FamilyName        string
	Email             string
	Password          string
	ChangeRequired    bool
	Verified          bool
}

// validate 校验必填项；这里返回 error 而不是直接退出，方便单元测试覆盖各种入参组合
func (p createUserParams) validate() error {
	switch {
	case p.OrgID == "":
		return errors.New("缺少必填参数: orgID")
	case p.Email == "":
		return errors.New("缺少必填参数: email")
	default:
		return nil
	}
}

// buildCreateUserRequest 把入参组装成 CreateUser 请求。
// 可选字段仅在非空时才设置，避免用零值覆盖服务端的默认值。
func buildCreateUserRequest(p createUserParams) *pb.CreateUserRequest {
	// 邮箱：默认发送验证邮件；明确要求时标记为已验证
	humanEmail := &pb.SetHumanEmail{
		Email: p.Email,
	}
	if p.Verified {
		humanEmail.Verification = &pb.SetHumanEmail_IsVerified{IsVerified: true}
	}

	// human 用户的信息由档案、邮箱和初始密码三部分组成
	humanUser := &pb.CreateUserRequest_Human{
		Profile: &pb.SetHumanProfile{
			GivenName:         p.GivenName,
			FamilyName:        p.FamilyName,
			PreferredLanguage: &p.PreferredLanguage,
		},
		Email: humanEmail,
	}
	// 未设置密码时，用户会通过收到的初始化邮件自行设置密码
	if p.Password != "" {
		humanUser.PasswordType = &pb.CreateUserRequest_Human_Password{
			Password: &pb.Password{
				Password:       p.Password,
				ChangeRequired: p.ChangeRequired,
			},
		}
	}

	req := &pb.CreateUserRequest{
		// 建议显式指定组织 ID，不要依赖连接上的组织上下文
		OrganizationId: p.OrgID,
		// UserType 是一个 oneof：Human_ 表示普通用户，Machine_ 表示机器/服务账号
		UserType: &pb.CreateUserRequest_Human_{
			Human: humanUser,
		},
	}
	if p.Username != "" {
		req.Username = &p.Username
	}
	return req
}

// createUser 通过 User API v2 创建普通用户
func createUser(ctx context.Context, client userCreator, p createUserParams) (*pb.CreateUserResponse, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	resp, err := client.CreateUser(ctx, buildCreateUserRequest(p))
	if err != nil {
		return nil, fmt.Errorf("创建用户失败: %w", err)
	}
	return resp, nil
}

// 该示例演示如何通过 User API v2 创建一个普通用户（human user）。
// 运行示例：
//
//	ZITADEL_KEY_PATH=path/to/jwt-key.json go run example/user/create_user \
//	  -issuer https://<instance>.zitadel.cloud \
//	  -api <instance>.zitadel.cloud:443 \
//	  -orgID <orgID> \
//	  -email john.doe@example.com \
//	  -preferredLanguage zh \
//	  -givenName John \
//	  -familyName Doe \
//	  -password "Secr3t-Passw0rd!"
//
// 私有化部署时 issuer 为实例外部 HTTPS 地址，api 为 gRPC 地址（主机名:端口，不带 https://）：
//
//	-issuer https://zitadel.corp.example.com -api zitadel.corp.example.com:443
//
// 调用该 API 需要具备 user.write 权限。
func main() {
	flag.Parse()

	ctx := context.Background()

	// 为 User API v2 创建一个客户端，需要提供：
	// - issuer（例如 https://acme-dtfhdg.zitadel.cloud）
	// - api（例如 acme-dtfhdg.zitadel.cloud:443）
	// - scopes（需包含 ZITADEL 的项目 ID），
	// - 一个 JWT Profile 令牌来源（例如你的 key json 路径），若未提供，则会从环境变量 ZITADEL_KEY_PATH 设置的路径读取该文件
	client, err := userv2.NewClient(
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

	resp, err := createUser(ctx, client, createUserParams{
		OrgID:             *orgID,
		Username:          *username,
		PreferredLanguage: *preferredLanguage,
		GivenName:         *givenName,
		FamilyName:        *familyName,
		Email:             *email,
		Password:          *password,
		ChangeRequired:    *changeRequired,
		Verified:          *verified,
	})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("user %s created on: %s", resp.GetId(), resp.GetCreationDate().AsTime())
}
