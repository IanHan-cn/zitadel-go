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

// fakeUserDeleter 替换真实的 UserServiceClient：
// 分别统计预览（GetUserByID）与删除（DeleteUser）的调用情况
type fakeUserDeleter struct {
	// 内嵌生成的客户端接口：未实现的其它方法保持为 nil，本例只会调用 GetUserByID / DeleteUser
	pb.UserServiceClient
	getResponse   *pb.GetUserByIDResponse
	getRequest    *pb.GetUserByIDRequest
	getErr        error
	getCalls      int
	deleteRequest *pb.DeleteUserRequest
	deleteErr     error
	deleteCalls   int
}

func (f *fakeUserDeleter) GetUserByID(_ context.Context, in *pb.GetUserByIDRequest, _ ...grpc.CallOption) (*pb.GetUserByIDResponse, error) {
	f.getCalls++
	f.getRequest = in
	return f.getResponse, f.getErr
}

func (f *fakeUserDeleter) DeleteUser(_ context.Context, in *pb.DeleteUserRequest, _ ...grpc.CallOption) (*pb.DeleteUserResponse, error) {
	f.deleteCalls++
	f.deleteRequest = in
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return &pb.DeleteUserResponse{}, nil
}

func TestDeleteUser_Table(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		confirm        bool
		getErr         error
		deleteErr      error
		expectErr      string
		expectDeleted  bool
		expectGetCalls int
		expectDelCalls int
	}{
		{
			name:      "1_MissingUserID_DoesNotCallAPI",
			userID:    "",
			confirm:   true,
			expectErr: "缺少必填参数: userID",
		},
		{
			// 未确认时只预览，绝不发起删除，避免误删
			name:           "2_NoConfirm_PreviewOnly",
			userID:         "user-1",
			confirm:        false,
			expectDeleted:  false,
			expectGetCalls: 1,
			expectDelCalls: 0,
		},
		{
			name:           "3_Confirm_DeletesOnce",
			userID:         "user-1",
			confirm:        true,
			expectDeleted:  true,
			expectGetCalls: 0,
			expectDelCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeUserDeleter{
				getResponse: &pb.GetUserByIDResponse{User: &pb.User{UserId: tt.userID, Username: "john"}},
				getErr:      tt.getErr,
				deleteErr:   tt.deleteErr,
			}

			result, err := deleteUser(context.Background(), fake, tt.userID, tt.confirm)

			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				assert.Zero(t, fake.getCalls)
				assert.Zero(t, fake.deleteCalls)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectDeleted, result.Deleted)
			assert.Equal(t, tt.expectGetCalls, fake.getCalls)
			assert.Equal(t, tt.expectDelCalls, fake.deleteCalls)
		})
	}
}

func TestDeleteUser_PreviewReturnsUser(t *testing.T) {
	fake := &fakeUserDeleter{getResponse: &pb.GetUserByIDResponse{
		User: &pb.User{UserId: "user-1", Username: "john"},
	}}

	result, err := deleteUser(context.Background(), fake, "user-1", false)

	require.NoError(t, err)
	assert.False(t, result.Deleted)
	require.NotNil(t, result.Preview)
	assert.Equal(t, "user-1", result.Preview.GetUserId())
	assert.Equal(t, "john", result.Preview.GetUsername())
	assert.Nil(t, result.Preview.GetDetails())
	require.True(t, proto.Equal(&pb.GetUserByIDRequest{UserId: "user-1"}, fake.getRequest))
}

func TestDeleteUser_ConfirmPassesUserID(t *testing.T) {
	fake := &fakeUserDeleter{}

	result, err := deleteUser(context.Background(), fake, "user-42", true)

	require.NoError(t, err)
	assert.True(t, result.Deleted)
	require.True(t, proto.Equal(&pb.DeleteUserRequest{UserId: "user-42"}, fake.deleteRequest))
}

func TestDeleteUser_PreviewError_IsWrapped(t *testing.T) {
	sentinel := errors.New("user not found")
	fake := &fakeUserDeleter{getErr: sentinel}

	_, err := deleteUser(context.Background(), fake, "user-1", false)

	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
	assert.ErrorContains(t, err, "预览用户失败")
	assert.Zero(t, fake.deleteCalls)
}

func TestDeleteUser_DeleteError_IsWrapped(t *testing.T) {
	sentinel := errors.New("permission denied")
	fake := &fakeUserDeleter{deleteErr: sentinel}

	result, err := deleteUser(context.Background(), fake, "user-1", true)

	require.Error(t, err)
	require.ErrorIs(t, err, sentinel)
	assert.ErrorContains(t, err, "删除用户失败")
	assert.False(t, result.Deleted)
}
