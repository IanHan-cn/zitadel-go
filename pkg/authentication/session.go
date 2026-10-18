package authentication

import (
	"errors"
	"sync"
)

// Sessions 是会话存储的抽象。
type Sessions[T Ctx] interface {
	Set(id string, session T) error
	Get(id string) (T, error)
}

// InMemorySessions 通过将会话保存在应用内存中来实现 [Sessions] 接口。
//
// ⚠️  警告：不适合在生产环境中使用
//
// 该实现在生产环境中存在根本性缺陷，会给真实应用带来严重问题：
//
// 可靠性问题：
//   - 当应用重启、崩溃或重新部署时，所有用户会话会瞬间消失——导致每个用户都必须重新登录
//   - 零容错能力——任何服务端故障都会让所有活跃会话失效
//
// 可扩展性问题：
//   - 无法运行多个服务实例——会话只存在于单台服务器上，负载均衡器会随机导致用户登录态失效
//   - 无法应对流量高峰或进行负载分摊
//
// 安全与资源问题：
//   - 内存无限增长——旧会话永不过期也不会被清理
//   - 最终会耗尽全部可用内存，导致服务器崩溃
//   - 无法吊销会话，也无法应对安全事件
//
// 生产环境替代方案：
//   - 使用 [WithCookieSession]() 实现无状态的加密 Cookie 会话
//   - 使用 Redis/Memcached 实现快速的服务端会话
//   - 使用数据库存储实现持久化会话
//   - 自行实现 [Sessions] 接口，接入自定义存储
//
// 适用场景：仅限本地开发、单元测试和概念验证演示。
type InMemorySessions[T Ctx] struct {
	mu       sync.RWMutex
	sessions map[string]T
}

// NewInMemorySessions 创建一个新的内存会话存储。
//
// ⚠️  警告：请勿在生产环境中使用——这会让你的应用出问题！
// 具体原因请参阅 [InMemorySessions] 的文档说明。
//
// 生产环境建议改用 [WithCookieSession]() 实现无状态会话，
// 或者实现一个正式的会话存储。
//
// 仅用于本地开发、测试或学习目的。
func NewInMemorySessions[T Ctx]() Sessions[T] {
	return &InMemorySessions[T]{
		sessions: make(map[string]T),
	}
}

func (s *InMemorySessions[T]) Get(id string) (T, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.sessions[id]
	if !ok {
		return t, errors.New("session not found")
	}
	return t, nil
}

func (s *InMemorySessions[T]) Set(id string, session T) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
	return nil
}
