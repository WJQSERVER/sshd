package middleware

import (
	"net"
)

// AuthContext 存储认证过程中的上下文信息
// 它会在中间件之间以及中间件和核心认证处理器之间传递
type AuthContext struct {
	User        string      // 尝试登录的用户名
	RemoteAddr  net.Addr    // 客户端的网络地址
	AuthMethod  string      // 尝试的认证方法 (例如, "password", "publickey")
	SessionID   []byte      // 会话ID (如果适用)
	ClientVersion []byte  // 客户端版本信息 (如果适用)
	ServerVersion []byte  // 服务端版本信息 (如果适用)
	Permissions *Permissions // 用户成功认证后获得的权限 (中间件可以修改)
	// 用于中间件存储自定义数据, 避免 AuthContext 结构膨胀
	// 注意: 并发访问需要自行处理同步
	customData map[string]interface{}
	// 标记请求是否已被某个中间件处理并终止
	isAborted bool
	// 存储发生的错误, 中间件可以设置此错误
	err error
}

// NewAuthContext 创建一个新的 AuthContext 实例
func NewAuthContext(user string, remoteAddr net.Addr, authMethod string) *AuthContext {
	return &AuthContext{
		User:       user,
		RemoteAddr: remoteAddr,
		AuthMethod: authMethod,
		customData: make(map[string]interface{}),
	}
}

// Set 将自定义数据存入上下文
func (c *AuthContext) Set(key string, value interface{}) {
	if c.customData == nil {
		c.customData = make(map[string]interface{})
	}
	c.customData[key] = value
}

// Get 从上下文中获取自定义数据
func (c *AuthContext) Get(key string) (interface{}, bool) {
	value, exists := c.customData[key]
	return value, exists
}

// Abort 标记请求处理链终止
// 后续的中间件 (如果调用 Next) 和核心处理器将不会被执行
func (c *AuthContext) Abort() {
	c.isAborted = true
}

// AbortWithError 标记请求处理链终止, 并记录一个错误
func (c *AuthContext) AbortWithError(err error) {
	c.err = err
	c.Abort()
}

// IsAborted 返回请求是否已被标记为终止
func (c *AuthContext) IsAborted() bool {
	return c.isAborted
}

// Error 返回在处理过程中发生的错误 (如果有)
func (c *AuthContext) Error() error {
	return c.err
}

// Permissions 定义了用户认证成功后可能获得的权限信息
// 这是一个示例结构, 具体字段可以根据实际需求调整
type Permissions struct {
	CanPortForward      bool
	CanExecuteCommands  bool
	AllowedCommands     []string
	Environment         []string
	// SSHPAExtensions 存储需要传递给 ssh.Permissions.Extensions 的键值对
	SSHPAExtensions      map[string]string
}

// AuthHandlerFunc 定义了核心认证逻辑的函数签名
// 中间件最终会调用这个类型的函数, 或者调用链中的下一个中间件
type AuthHandlerFunc func(*AuthContext) (*Permissions, error)

// MiddlewareFunc 定义了认证中间件的函数签名
// 它接收下一个处理器 (可以是另一个中间件或最终的核心认证处理器)
// 并返回一个处理器, 该处理器封装了中间件的逻辑
type MiddlewareFunc func(AuthHandlerFunc) AuthHandlerFunc

// ChainBuilder 用于构建中间件链
type ChainBuilder struct {
	middlewares []MiddlewareFunc
}

// NewChainBuilder 创建一个新的 ChainBuilder
func NewChainBuilder() *ChainBuilder {
	return &ChainBuilder{
		middlewares: []MiddlewareFunc{},
	}
}

// Use 添加一个或多个中间件到链中
// 中间件将按照它们被添加的顺序执行
func (cb *ChainBuilder) Use(middlewares ...MiddlewareFunc) {
	cb.middlewares = append(cb.middlewares, middlewares...)
}

// Then 将注册的中间件链接起来, 并与最终的核心处理函数结合
// 返回一个单一的 AuthHandlerFunc, 代表整个处理链的入口
func (cb *ChainBuilder) Then(finalHandler AuthHandlerFunc) AuthHandlerFunc {
	if finalHandler == nil {
		// 如果没有最终处理器, 使用一个默认的空处理器
		// 这个处理器在被调用时什么也不做, 除非上下文已经被中止
		finalHandler = func(ctx *AuthContext) (*Permissions, error) {
			if ctx.IsAborted() {
				return nil, ctx.Error()
			}
			return nil, nil // 或者返回一个特定的错误/状态表示没有核心处理器
		}
	}

	// 从最后一个中间件开始, 向前回溯构建链
	// 每个中间件包装它之后的处理器 (下一个中间件或最终处理器)
	chainedHandler := finalHandler
	for i := len(cb.middlewares) - 1; i >= 0; i-- {
		chainedHandler = cb.middlewares[i](chainedHandler)
	}
	return chainedHandler
}

// Helper function to compose middlewares directly without a builder instance.
// This can be useful for simpler cases or for composing chains dynamically.

// Chain 将一组中间件与一个核心处理函数链接起来
// middlewares 参数中的中间件会按照它们在切片中的顺序依次执行
// 第一个中间件最先执行, 最后一个中间件在核心处理函数之前执行
func Chain(finalHandler AuthHandlerFunc, middlewares ...MiddlewareFunc) AuthHandlerFunc {
	if finalHandler == nil {
		finalHandler = func(ctx *AuthContext) (*Permissions, error) {
			if ctx.IsAborted() {
				return nil, ctx.Error()
			}
			return nil, nil
		}
	}

	chainedHandler := finalHandler
	for i := len(middlewares) - 1; i >= 0; i-- {
		chainedHandler = middlewares[i](chainedHandler)
	}
	return chainedHandler
}
