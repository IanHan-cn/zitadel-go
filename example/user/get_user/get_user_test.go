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

// fakeUserGetter 替换真实的 UserServiceClient，记录收到的请求并返回预设结果
type fakeUserGetter struct {
	// 内嵌生成的客户端接口：未实现的其它方法保持为 nil，本例只会调用 GetUserByID
	pb.UserServiceClient
	request  *pb.GetUserByIDRequest
	response *pb.GetUserByIDResponse
	err      error
	calls    int
}

func (f *fakeUserGetter) GetUserByID(_ context.Context, in *pb.GetUserByIDRequest, _ ...grpc.CallOption) (*pb.GetUserByIDResponse, error) {
	f.calls++
	f.request = in
	return f.response, f.err
}

func TestGetUser_Table(t *testing.T) {
	tests := []struct {
		name         string
		userID       string
		response     *pb.GetUserByIDResponse
		expectError  string
		expectUserID string
	}{
		{
			name:        "1_MissingUserID_DoesNotCallAPI",
			userID:      "",
			expectError: "缺少必填参数: userID",
		},
		{
			name:   "2_ReturnsUser",
			userID: "user-1",
			response: &pb.GetUserByIDResponse{
				User: &pb.User{
					UserId:   "user-1",
					Username: "john",
					Type: &pb.User_Human{Human: &pb.HumanUser{
						Profile: &pb.HumanProfile{GivenName: "John", FamilyName: "Doe"},
						Email:   &pb.HumanEmail{Email: "john@example.com", IsVerified: true},
					}},
				},
			},
			expectUserID: "user-1",
		},
		{
			// 服务端未返回 User 时，只能通过 Get* 访问器取值，避免解引用空指针
			name:         "3_EmptyResponse_ReturnsNilUser",
			userID:       "user-404",
			response:     &pb.GetUserByIDResponse{},
			expectUserID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeUserGetter{response: tt.response}

			user, err := getUser(context.Background(), fake, tt.userID)

			if tt.expectError != "" {
				require.EqualError(t, err, tt.expectError)
				assert.Zero(t, fake.calls, "参数不合法时不应发起任何调用")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectUserID, user.GetUserId())
			assert.Equal(t, 1, fake.calls)
			assert.Equal(t, tt.userID, fake.request.GetUserId())
		})
	}
}

func TestGetUser_HumanFieldsAreReadable(t *testing.T) {
	fake := &fakeUserGetter{response: &pb.GetUserByIDResponse{
		User: &pb.User{
			UserId:   "user-1",
			Username: "john",
			Type: &pb.User_Human{Human: &pb.HumanUser{
				Profile: &pb.HumanProfile{GivenName: "John", FamilyName: "Doe", NickName: strPtr("Johnny")},
				Email:   &pb.HumanEmail{Email: "john@example.com", IsVerified: true},
			}},
		},
	}}

	user, err := getUser(context.Background(), fake, "user-1")

	require.NoError(t, err)
	assert.Equal(t, "John", user.GetHuman().GetProfile().GetGivenName())
	assert.Equal(t, "Doe", user.GetHuman().GetProfile().GetFamilyName())
	assert.Equal(t, "Johnny", user.GetHuman().GetProfile().GetNickName())
	assert.Equal(t, "john@example.com", user.GetHuman().GetEmail().GetEmail())
	assert.True(t, user.GetHuman().GetEmail().GetIsVerified())
	// 机器用户字段不应被设置
	assert.Nil(t, user.GetMachine())
}

func TestGetUser_ClientError_IsWrapped(t *testing.T) {
	sentinel := errors.New("user not found")
	fake := &fakeUserGetter{err: sentinel}

	_, err := getUser(context.Background(), fake, "user-1")

	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
	assert.ErrorContains(t, err, "查询用户失败")
}

// 保证 buildGetUserByIDRequest 行为稳定：UserId 必须与入参完全一致
func TestGetUser_RequestIsBuiltFromUserID(t *testing.T) {
	fake := &fakeUserGetter{response: &pb.GetUserByIDResponse{}}

	_, err := getUser(context.Background(), fake, "user-42")

	require.NoError(t, err)
	require.True(t, proto.Equal(&pb.GetUserByIDRequest{UserId: "user-42"}, fake.request))
}
