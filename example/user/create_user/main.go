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
	domain            = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	keyPath           = flag.String("key", "", "path to your service user's key.json; 为空时回退到环境变量 ZITADEL_KEY_PATH")
	orgID             = flag.String("orgID", "", "orgID of the organization the user is created in (required)")
	username          = flag.String("username", "", "username of the new user; defaults to the email if empty")
	preferredLanguage = flag.String("preferredLanguage", "", "preferred language of the new user; defaults to en if empty")
	givenName         = flag.String("givenName", "", "given (first) name of the new user")
	familyName        = flag.String("familyName", "", "family (last) name of the new user")
	email             = flag.String("email", "", "email of the new user (required)")
	password          = flag.String("password", "", "initial password; 建议改用环境变量 ZITADEL_USER_PASSWORD，避免明文出现在命令行中；都为空时不设置密码，用户通过初始化邮件自行设置")
	changeRequired    = flag.Bool("changeRequired", true, "require the user to change the password on the first login")
	verified          = flag.Bool("verified", false, "mark the email as verified; if false a verification email is sent")
)

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
	humanProfile := &pb.SetHumanProfile{
		GivenName:  p.GivenName,
		FamilyName: p.FamilyName,
	}
	// PreferredLanguage 是可选字段：留空时必须保持未设置，
	// 否则服务端会收到显式的空语言，而不是使用默认语言
	if p.PreferredLanguage != "" {
		humanProfile.PreferredLanguage = &p.PreferredLanguage
	}
	humanUser := &pb.CreateUserRequest_Human{
		Profile: humanProfile,
		Email:   humanEmail,
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
func createUser(ctx context.Context, client pb.UserServiceClient, p createUserParams) (*pb.CreateUserResponse, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	resp, err := client.CreateUser(ctx, buildCreateUserRequest(p))
	if err != nil {
		return nil, fmt.Errorf("创建用户失败: %w", err)
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

// resolvePassword 读取初始密码：优先使用环境变量，避免密码明文出现在 ps 输出和 shell 历史中
func resolvePassword() string {
	if p := os.Getenv("ZITADEL_USER_PASSWORD"); p != "" {
		return p
	}
	return *password
}

// 该示例演示如何通过 User API v2 创建一个普通用户（human user）。
// 运行示例：
//
//	ZITADEL_USER_PASSWORD='Secr3t-Passw0rd!' go run example/user/create_user \
//	  -domain <instance>.zitadel.cloud \
//	  -key path/to/jwt-key.json \
//	  -orgID <orgID> \
//	  -email john.doe@example.com \
//	  -preferredLanguage zh \
//	  -givenName John \
//	  -familyName Doe
//
// 密钥文件路径也可以通过环境变量 ZITADEL_KEY_PATH 提供（-key 优先级更高）。
//
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

	resp, err := createUser(ctx, api.UserServiceV2(), createUserParams{
		OrgID:             *orgID,
		Username:          *username,
		PreferredLanguage: *preferredLanguage,
		GivenName:         *givenName,
		FamilyName:        *familyName,
		Email:             *email,
		Password:          resolvePassword(),
		ChangeRequired:    *changeRequired,
		Verified:          *verified,
	})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("user %s created on: %s", resp.GetId(), resp.GetCreationDate().AsTime())
}
