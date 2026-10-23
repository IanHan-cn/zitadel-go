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
	domain      = flag.String("domain", "", "your ZITADEL instance domain (in the form: <instance>.zitadel.cloud or <yourdomain>)")
	keyPath     = flag.String("key", "", "path to your service user's key.json; 为空时回退到环境变量 ZITADEL_KEY_PATH")
	userID      = flag.String("userID", "", "userID of the user to update (required)")
	username    = flag.String("username", "", "新的用户名；留空表示不修改")
	givenName   = flag.String("givenName", "", "新的名字；留空表示不修改")
	familyName  = flag.String("familyName", "", "新的姓氏；留空表示不修改")
	nickName    = flag.String("nickName", "", "新的昵称；留空表示不修改")
	displayName = flag.String("displayName", "", "新的展示名称；留空表示不修改")
)

// updateUserParams 汇总修改用户资料所需的全部入参
type updateUserParams struct {
	UserID      string
	Username    string
	GivenName   string
	FamilyName  string
	NickName    string
	DisplayName string
}

// hasChanges 判断是否至少提供了一个待更新字段；UpdateUser 是部分更新接口，
// 一个字段都没给的话本次调用没有意义
func (p updateUserParams) hasChanges() bool {
	return p.Username != "" ||
		p.GivenName != "" ||
		p.FamilyName != "" ||
		p.NickName != "" ||
		p.DisplayName != ""
}

// buildUpdateProfile 只把非空字段放入 Profile。
// Profile 里的字段都是可选指针：设置为空字符串会清空用户已有资料，因此空串一律不设置。
func buildUpdateProfile(p updateUserParams) *pb.UpdateUserRequest_Human_Profile {
	profile := &pb.UpdateUserRequest_Human_Profile{}
	if p.GivenName != "" {
		profile.GivenName = &p.GivenName
	}
	if p.FamilyName != "" {
		profile.FamilyName = &p.FamilyName
	}
	if p.NickName != "" {
		profile.NickName = &p.NickName
	}
	if p.DisplayName != "" {
		profile.DisplayName = &p.DisplayName
	}
	return profile
}

// buildUpdateUserRequest 把入参组装成 UpdateUser 请求
func buildUpdateUserRequest(p updateUserParams) *pb.UpdateUserRequest {
	req := &pb.UpdateUserRequest{
		UserId: p.UserID,
		UserType: &pb.UpdateUserRequest_Human_{
			Human: &pb.UpdateUserRequest_Human{
				Profile: buildUpdateProfile(p),
			},
		},
	}
	if p.Username != "" {
		req.Username = &p.Username
	}
	return req
}

// updateUser 通过 User API v2 部分更新用户信息
func updateUser(ctx context.Context, client pb.UserServiceClient, p updateUserParams) (*pb.UpdateUserResponse, error) {
	switch {
	case p.UserID == "":
		return nil, errors.New("缺少必填参数: userID")
	case !p.hasChanges():
		return nil, errors.New("没有需要更新的字段：请至少提供 username/givenName/familyName/nickName/displayName 中的一项")
	}
	resp, err := client.UpdateUser(ctx, buildUpdateUserRequest(p))
	if err != nil {
		return nil, fmt.Errorf("更新用户失败: %w", err)
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

// 该示例演示如何通过 User API v2 修改普通用户的资料。
// 运行示例：
//
//	go run example/user/update_user \
//	  -domain <instance>.zitadel.cloud \
//	  -key path/to/jwt-key.json \
//	  -userID <userID> \
//	  -givenName John \
//	  -familyName Doe
//
// 密钥文件路径也可以通过环境变量 ZITADEL_KEY_PATH 提供（-key 优先级更高）。
//
// UpdateUser 是部分更新接口：未提供的字段保持原值不变。
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

	resp, err := updateUser(ctx, api.UserServiceV2(), updateUserParams{
		UserID:      *userID,
		Username:    *username,
		GivenName:   *givenName,
		FamilyName:  *familyName,
		NickName:    *nickName,
		DisplayName: *displayName,
	})
	if err != nil {
		log.Fatalln("call failed: ", err)
	}
	log.Printf("user updated on: %s", resp.GetChangeDate().AsTime())
}
