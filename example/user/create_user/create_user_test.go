package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

// strPtr 返回字符串的指针，用于在期望值中表达 proto 的可选字段
func strPtr(s string) *string {
	return &s
}

// fakeUserCreator 替换真实的 UserServiceClient，记录收到的请求并返回预设结果，
// 这样单元测试无需连接任何 ZITADEL 实例
type fakeUserCreator struct {
	request  *pb.CreateUserRequest
	response *pb.CreateUserResponse
	err      error
	calls    int
}

func (f *fakeUserCreator) CreateUser(_ context.Context, in *pb.CreateUserRequest, _ ...grpc.CallOption) (*pb.CreateUserResponse, error) {
	f.calls++
	f.request = in
	return f.response, f.err
}

func TestCreateUserParams_Validate_Table(t *testing.T) {
	tests := []struct {
		name        string
		params      createUserParams
		expectError string
	}{
		{
			name:        "1_MissingOrgID",
			params:      createUserParams{Email: "john@example.com"},
			expectError: "缺少必填参数: orgID",
		},
		{
			name:        "2_MissingEmail",
			params:      createUserParams{OrgID: "org-1"},
			expectError: "缺少必填参数: email",
		},
		{
			name:   "3_RequiredFieldsPresent",
			params: createUserParams{OrgID: "org-1", Email: "john@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.validate()
			if tt.expectError == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.expectError)
		})
	}
}

func TestBuildCreateUserRequest_Table(t *testing.T) {
	tests := []struct {
		name   string
		params createUserParams
		expect *pb.CreateUserRequest
	}{
		{
			name: "1_AllFieldsProvided_VerifiedEmail",
			params: createUserParams{
				OrgID:          "org-1",
				Username:       "john",
				GivenName:      "John",
				FamilyName:     "Doe",
				Email:          "john@example.com",
				Password:       "Secr3t-Passw0rd!",
				ChangeRequired: true,
				Verified:       true,
			},
			expect: &pb.CreateUserRequest{
				OrganizationId: "org-1",
				Username:       strPtr("john"),
				UserType: &pb.CreateUserRequest_Human_{
					Human: &pb.CreateUserRequest_Human{
						Profile: &pb.SetHumanProfile{GivenName: "John", FamilyName: "Doe"},
						Email: &pb.SetHumanEmail{
							Email:        "john@example.com",
							Verification: &pb.SetHumanEmail_IsVerified{IsVerified: true},
						},
						PasswordType: &pb.CreateUserRequest_Human_Password{
							Password: &pb.Password{Password: "Secr3t-Passw0rd!", ChangeRequired: true},
						},
					},
				},
			},
		},
		{
			// 不传 username / password 时，这两个字段不应出现在请求里，
			// 否则服务端会以错误的零值处理（用户名默认为邮箱、由初始化邮件设置密码）
			name: "2_NoUsernameAndNoPassword_LeavesFieldsUnset",
			params: createUserParams{
				OrgID:    "org-1",
				Email:    "john@example.com",
				Verified: false,
			},
			expect: &pb.CreateUserRequest{
				OrganizationId: "org-1",
				UserType: &pb.CreateUserRequest_Human_{
					Human: &pb.CreateUserRequest_Human{
						Profile: &pb.SetHumanProfile{},
						Email:   &pb.SetHumanEmail{Email: "john@example.com"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCreateUserRequest(tt.params)
			require.True(t, proto.Equal(tt.expect, got),
				"请求体不符合预期\nwant: %v\ngot:  %v", tt.expect, got)
		})
	}
}

func TestCreateUser_Success(t *testing.T) {
	fake := &fakeUserCreator{response: &pb.CreateUserResponse{Id: "user-1"}}

	resp, err := createUser(context.Background(), fake, createUserParams{
		OrgID:    "org-1",
		Email:    "john@example.com",
		Password: "Secr3t-Passw0rd!",
	})

	require.NoError(t, err)
	assert.Equal(t, "user-1", resp.GetId())
	assert.Equal(t, 1, fake.calls)
	assert.Equal(t, "org-1", fake.request.GetOrganizationId())
	// 必须选择 Human 分支，才能创建普通用户而不是机器用户
	assert.NotNil(t, fake.request.GetHuman())
	assert.Nil(t, fake.request.GetMachine())
}

func TestCreateUser_InvalidParams_DoesNotCallAPI(t *testing.T) {
	fake := &fakeUserCreator{response: &pb.CreateUserResponse{Id: "user-1"}}

	_, err := createUser(context.Background(), fake, createUserParams{Email: "john@example.com"})

	require.EqualError(t, err, "缺少必填参数: orgID")
	assert.Zero(t, fake.calls, "参数不合法时不应发起任何调用")
}

func TestCreateUser_ClientError_IsWrapped(t *testing.T) {
	sentinel := errors.New("permission denied")
	fake := &fakeUserCreator{err: sentinel}

	_, err := createUser(context.Background(), fake, createUserParams{
		OrgID: "org-1",
		Email: "john@example.com",
	})

	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
	assert.ErrorContains(t, err, "创建用户失败")
}
