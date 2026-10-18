package middleware

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
)

type OrgInterceptor struct {
	orgID string
}

// NewOrgInterceptor 为每一次调用静态地设置组织上下文
//
// 如果你需要在不同请求间切换多个组织，请直接在调用处使用 SetOrgID 函数
// （参见 example/mgmt/mgmt.go）
func NewOrgInterceptor(orgID string) *OrgInterceptor {
	return &OrgInterceptor{
		orgID: orgID,
	}
}

func (interceptor *OrgInterceptor) Unary() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(SetOrgID(ctx, interceptor.orgID), method, req, reply, cc, opts...)
	}
}

func (interceptor *OrgInterceptor) Stream() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(SetOrgID(ctx, interceptor.orgID), desc, cc, method, opts...)
	}
}

// SetOrgID 传递用于组织上下文（即 API 调用在哪个组织下执行）的 orgID
func SetOrgID(ctx context.Context, orgID string) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		return metadata.AppendToOutgoingContext(ctx, client.OrgHeader, orgID)
	}
	md.Set(client.OrgHeader, orgID)
	return metadata.NewOutgoingContext(ctx, md)
}
