package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	object "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	pb "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

// fakeUserLister 替换真实的 UserServiceClient，记录收到的请求并返回预设结果
type fakeUserLister struct {
	request  *pb.ListUsersRequest
	response *pb.ListUsersResponse
	calls    int
}

func (f *fakeUserLister) ListUsers(_ context.Context, in *pb.ListUsersRequest, _ ...grpc.CallOption) (*pb.ListUsersResponse, error) {
	f.calls++
	f.request = in
	return f.response, nil
}

// errUserLister 用于覆盖服务端返回错误的场景
type errUserLister struct {
	request *pb.ListUsersRequest
	err     error
}

func (f *errUserLister) ListUsers(_ context.Context, in *pb.ListUsersRequest, _ ...grpc.CallOption) (*pb.ListUsersResponse, error) {
	f.request = in
	return nil, f.err
}

func TestBuildListUsersRequest_Table(t *testing.T) {
	tests := []struct {
		name   string
		params listUsersParams
		expect *pb.ListUsersRequest
	}{
		{
			// 无任何过滤条件：只带分页与排序，此时会返回调用者有权限查看的全部用户
			name:   "1_NoFilter_PaginationOnly",
			params: listUsersParams{Limit: 100, Offset: 0},
			expect: &pb.ListUsersRequest{
				Query:         &object.ListQuery{Limit: 100, Offset: 0, Asc: true},
				SortingColumn: pb.UserFieldName_USER_FIELD_NAME_USER_NAME,
			},
		},
		{
			name:   "2_OrganizationFilter",
			params: listUsersParams{OrgID: "org-1", Limit: 50, Offset: 20},
			expect: &pb.ListUsersRequest{
				Query:         &object.ListQuery{Limit: 50, Offset: 20, Asc: true},
				SortingColumn: pb.UserFieldName_USER_FIELD_NAME_USER_NAME,
				Queries: []*pb.SearchQuery{
					{
						Query: &pb.SearchQuery_OrganizationIdQuery{
							OrganizationIdQuery: &pb.OrganizationIdQuery{OrganizationId: "org-1"},
						},
					},
				},
			},
		},
		{
			// 多个过滤条件之间是 AND 关系，且顺序应与入参保持一致
			name: "3_AllFiltersCombined",
			params: listUsersParams{
				OrgID:    "org-1",
				Username: "john",
				Email:    "john@example.com",
				Limit:    10,
			},
			expect: &pb.ListUsersRequest{
				Query:         &object.ListQuery{Limit: 10, Asc: true},
				SortingColumn: pb.UserFieldName_USER_FIELD_NAME_USER_NAME,
				Queries: []*pb.SearchQuery{
					{
						Query: &pb.SearchQuery_OrganizationIdQuery{
							OrganizationIdQuery: &pb.OrganizationIdQuery{OrganizationId: "org-1"},
						},
					},
					{
						Query: &pb.SearchQuery_UserNameQuery{
							UserNameQuery: &pb.UserNameQuery{
								UserName: "john",
								Method:   object.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE,
							},
						},
					},
					{
						Query: &pb.SearchQuery_EmailQuery{
							EmailQuery: &pb.EmailQuery{
								EmailAddress: "john@example.com",
								Method:       object.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE,
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildListUsersRequest(tt.params)
			require.True(t, proto.Equal(tt.expect, got),
				"请求体不符合预期\nwant: %v\ngot:  %v", tt.expect, got)
		})
	}
}

func TestListUsers_ReturnsResponse(t *testing.T) {
	fake := &fakeUserLister{response: &pb.ListUsersResponse{
		Result: []*pb.User{{UserId: "user-1", Username: "john"}},
	}}

	resp, err := listUsers(context.Background(), fake, listUsersParams{OrgID: "org-1", Limit: 100})

	require.NoError(t, err)
	require.Len(t, resp.GetResult(), 1)
	assert.Equal(t, "user-1", resp.GetResult()[0].GetUserId())
	assert.Equal(t, 1, fake.calls)
	assert.Equal(t, uint32(100), fake.request.GetQuery().GetLimit())
}

func TestListUsers_ClientError_IsWrapped(t *testing.T) {
	fake := &errUserLister{err: assert.AnError}

	_, err := listUsers(context.Background(), fake, listUsersParams{Limit: 100})

	require.Error(t, err)
	require.ErrorIs(t, err, assert.AnError)
	assert.ErrorContains(t, err, "查询用户列表失败")
}
