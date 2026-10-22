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

// fakeUserUpdater 替换真实的 UserServiceClient，记录收到的请求并返回预设结果
type fakeUserUpdater struct {
	request  *pb.UpdateUserRequest
	response *pb.UpdateUserResponse
	err      error
	calls    int
}

func (f *fakeUserUpdater) UpdateUser(_ context.Context, in *pb.UpdateUserRequest, _ ...grpc.CallOption) (*pb.UpdateUserResponse, error) {
	f.calls++
	f.request = in
	return f.response, f.err
}

func TestUpdateUserParams_HasChanges_Table(t *testing.T) {
	tests := []struct {
		name   string
		params updateUserParams
		expect bool
	}{
		{
			name:   "1_EmptyParams_NoChanges",
			params: updateUserParams{},
			expect: false,
		},
		{
			name:   "2_OnlyUserID_NoChanges",
			params: updateUserParams{UserID: "user-1"},
			expect: false,
		},
		{
			name:   "3_GivenNameProvided",
			params: updateUserParams{UserID: "user-1", GivenName: "John"},
			expect: true,
		},
		{
			name:   "4_UsernameProvided",
			params: updateUserParams{UserID: "user-1", Username: "john.doe"},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, tt.params.hasChanges())
		})
	}
}

func TestBuildUpdateUserRequest_Table(t *testing.T) {
	tests := []struct {
		name   string
		params updateUserParams
		expect *pb.UpdateUserRequest
	}{
		{
			// Profile 中的字段都是可选指针：未提供的字段必须保持 nil，
			// 若设置成空字符串，服务端会把用户已有的资料清空
			name:   "1_OnlyProvidedFieldsAreSet",
			params: updateUserParams{UserID: "user-1", GivenName: "John"},
			expect: &pb.UpdateUserRequest{
				UserId: "user-1",
				UserType: &pb.UpdateUserRequest_Human_{
					Human: &pb.UpdateUserRequest_Human{
						Profile: &pb.UpdateUserRequest_Human_Profile{
							GivenName: strPtr("John"),
						},
					},
				},
			},
		},
		{
			name: "2_FullProfileAndUsername",
			params: updateUserParams{
				UserID:      "user-1",
				Username:    "john.doe",
				GivenName:   "John",
				FamilyName:  "Doe",
				NickName:    "Johnny",
				DisplayName: "John Doe",
			},
			expect: &pb.UpdateUserRequest{
				UserId:   "user-1",
				Username: strPtr("john.doe"),
				UserType: &pb.UpdateUserRequest_Human_{
					Human: &pb.UpdateUserRequest_Human{
						Profile: &pb.UpdateUserRequest_Human_Profile{
							GivenName:   strPtr("John"),
							FamilyName:  strPtr("Doe"),
							NickName:    strPtr("Johnny"),
							DisplayName: strPtr("John Doe"),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildUpdateUserRequest(tt.params)
			require.True(t, proto.Equal(tt.expect, got),
				"请求体不符合预期\nwant: %v\ngot:  %v", tt.expect, got)
		})
	}
}

func TestUpdateUser_Table(t *testing.T) {
	tests := []struct {
		name       string
		params     updateUserParams
		expectErr  string
		expectCall bool
	}{
		{
			name:      "1_MissingUserID_DoesNotCallAPI",
			params:    updateUserParams{GivenName: "John"},
			expectErr: "缺少必填参数: userID",
		},
		{
			name:      "2_NoChanges_DoesNotCallAPI",
			params:    updateUserParams{UserID: "user-1"},
			expectErr: "没有需要更新的字段：请至少提供 username/givenName/familyName/nickName/displayName 中的一项",
		},
		{
			name:       "3_ValidParams_CallsAPI",
			params:     updateUserParams{UserID: "user-1", GivenName: "John"},
			expectCall: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeUserUpdater{response: &pb.UpdateUserResponse{}}

			resp, err := updateUser(context.Background(), fake, tt.params)

			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				assert.Zero(t, fake.calls, "参数不合法时不应发起任何调用")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 1, fake.calls)
			assert.Equal(t, tt.params.UserID, fake.request.GetUserId())
			assert.NotNil(t, resp)
		})
	}
}

func TestUpdateUser_ClientError_IsWrapped(t *testing.T) {
	sentinel := errors.New("permission denied")
	fake := &fakeUserUpdater{err: sentinel}

	_, err := updateUser(context.Background(), fake, updateUserParams{UserID: "user-1", GivenName: "John"})

	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
	assert.ErrorContains(t, err, "更新用户失败")
}
