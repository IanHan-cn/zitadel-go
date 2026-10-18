package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v3alpha "github.com/zitadel/zitadel-go/v3/example/api/grpc/proto"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/grpc/middleware"
)

var _ v3alpha.ExampleServiceServer = (*Server)(nil)

var (
	// 该列表用于指定调用各个端点所需的授权检查。
	// 若某个端点（例如 [v3alpha.ExampleService_Healthz_FullMethodName]）未被加入列表，则它将被公开访问。
	// 通过添加具体的 [authorization.CheckOption]，可以定义诸如角色检查（[authorization.WithRole]）之类的额外要求。
	checks = map[string][]authorization.CheckOption{
		v3alpha.ExampleService_ListTasks_FullMethodName: nil,
		v3alpha.ExampleService_AddTask_FullMethodName:   {authorization.WithRole("admin")},
		v3alpha.ExampleService_AddTasks_FullMethodName:  {authorization.WithRole("admin")},
	}
)

func NewServer(mw *middleware.Interceptor[*oauth.IntrospectionContext]) *Server {
	return &Server{
		tasks: make([]string, 0),
		mw:    mw,
	}
}

type Server struct {
	v3alpha.UnimplementedExampleServiceServer

	mw *middleware.Interceptor[*oauth.IntrospectionContext]

	// tasks 用于在内存中保存一个列表，供受保护的端点使用
	tasks []string
}

// Healthz 任何人都可以访问，它始终返回 "OK" 以表明 API 正在运行
func (s *Server) Healthz(_ context.Context, _ *v3alpha.HealthzRequest) (*v3alpha.HealthzResponse, error) {
	return &v3alpha.HealthzResponse{
		Health: "OK",
	}, nil
}

// ListTasks 仅在持有有效授权（本例中为有效的 access_token / PAT）时才可访问。
// 它会列出所有已保存的任务。若用户被授予了 `admin` 角色，
// 还会额外添加一条提示他去新建任务的任务项。
func (s *Server) ListTasks(ctx context.Context, _ *v3alpha.ListTasksRequest) (*v3alpha.ListTasksResponse, error) {
	// 借助 [middleware.Context] 函数，我们可以获取已授权用户的信息。
	// 本例仅通过提供的方法打印用户 ID，并通过直接访问
	// 带类型的 [*oauth.IntrospectionContext] 的字段来打印用户名。
	authCtx := s.mw.Context(ctx)
	slog.Info("user accessed task list", "id", authCtx.UserID(), "username", authCtx.Username)

	// 虽然任何已授权用户都可以访问该端点，但你可能会想在
	// 用户被授予某个特定角色时采取额外操作。本例中会提示 `admin` 去新建任务：
	taskList := s.tasks
	if authCtx.IsGrantedRole("admin") {
		taskList = append(taskList, "create a new task with `AddTask`")
	}

	return &v3alpha.ListTasksResponse{
		Tasks: taskList,
	}, nil
}

// AddTask 仅在持有有效授权且被授予 `admin` 角色（在任意组织内）时才可访问。
// 它会将传入的任务添加到已有的任务列表中。
func (s *Server) AddTask(ctx context.Context, req *v3alpha.AddTaskRequest) (*v3alpha.AddTaskResponse, error) {
	// 获取传入的任务，不接受空值
	if req.GetTask() == "" {
		return nil, status.Error(codes.InvalidArgument, "task must not be empty")
	}

	// 既然不为空，就把它加入已有的列表
	s.tasks = append(s.tasks, req.GetTask())

	// 由于我们只需要已授权用户的 userID，不需要其他特定数据，因此可以直接使用 [authorization.UserID]
	slog.Info("admin added task", "id", authorization.UserID(ctx), "task", req.GetTask())

	// 告知管理员已成功添加
	return &v3alpha.AddTaskResponse{
		Added: fmt.Sprintf("task `%s` added", req.GetTask()),
	}, nil
}

// AddTasks 仅在持有有效授权且被授予 `admin` 角色（在任意组织内）时才可访问。
// 它演示了 gRPC 客户端流可以像标准 RPC 方法一样使用。
// 同样会把传入的一个或多个任务添加到已有的任务列表中。
func (s *Server) AddTasks(stream v3alpha.ExampleService_AddTasksServer) error {
	var count uint32
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			// 客户端流已结束，我们来检查一下列表
			if count == 0 {
				return status.Error(codes.InvalidArgument, "no task provided")
			}

			// 将成功添加的任务数量返回给客户端
			return stream.SendAndClose(&v3alpha.AddTasksResponse{Added: count})
		}
		if err != nil {
			return err
		}

		// 若没有出错，就检查任务是否为空，然后直接将其加入列表。
		// 我们还会再次记录日志，并对数量进行累加。
		if req.GetTask() != "" {
			s.tasks = append(s.tasks, req.GetTask())
			slog.Info("admin added task", "id", authorization.UserID(stream.Context()), "task", req.GetTask())
			count++
		}
	}
}
