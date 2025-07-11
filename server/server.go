package server

import (
	"errors"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"sshd/internal/middleware" // 新增导入
	"sshd/config"

	"golang.org/x/crypto/ssh"
)

// SSHServer 定义了 SSH 服务器的结构.
type SSHServer struct {
	config                *config.Config
	listener              net.Listener
	sshConfig             *ssh.ServerConfig
	authMiddlewareBuilder *middleware.ChainBuilder // 新增字段
}

// NewServer 是 SSHServer 的构造函数, 封装了所有初始化逻辑.
func NewServer(cfg *config.Config) (*SSHServer, error) {
	signer, err := loadOrCreateHostKey(cfg)
	if err != nil {
		return nil, fmt.Errorf("加载或创建主机密钥失败: %w", err)
	}

	// 初始化中间件构建器
	mwBuilder := middleware.NewChainBuilder()

	// 如果在配置中启用了 Fail2Ban, 则内置它
	if cfg.Fail2Ban.Enabled {
		f2bConcreteConfig := middleware.Fail2BanMiddlewareConfig{
			MaxAttempts: cfg.Fail2Ban.MaxAttempts,
			FindTime:    cfg.Fail2Ban.FindTime,
			BanTime:     cfg.Fail2Ban.BanTime,
			Whitelist:   cfg.Fail2Ban.Whitelist,
		}
		fail2banMW, err := middleware.NewFail2BanMiddleware(f2bConcreteConfig)
		if err != nil {
			log.Printf("警告: 初始化内置 Fail2Ban 中间件失败: %v. SSHD 将在没有它的情况下运行.", err)
		} else {
			log.Println("内置 Fail2Ban 中间件已启用并注册.")
			mwBuilder.Use(fail2banMW.Handler())
		}
	}

	sshCfg := &ssh.ServerConfig{
		// PasswordCallback 和 PublicKeyCallback 将在这里使用中间件链
	}
	sshCfg.AddHostKey(signer)

	// 创建 SSHServer 实例, 以便回调可以访问 authMiddlewareBuilder
	s := &SSHServer{
		config:                cfg,
		sshConfig:             sshCfg,
		authMiddlewareBuilder: mwBuilder,
	}

	// 设置密码认证回调
	sshCfg.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		authCtx := middleware.NewAuthContext(conn.User(), conn.RemoteAddr(), "password")
		authCtx.Set("password", string(password))
		authCtx.ClientVersion = conn.ClientVersion()
		authCtx.SessionID = conn.SessionID()

		coreAuthFunc := func(currentCtx *middleware.AuthContext) (*middleware.Permissions, error) {
			return CorePasswordAuthenticator(s.config, currentCtx)
		}
		chainedHandler := s.authMiddlewareBuilder.Then(coreAuthFunc)
		mwPerms, err := chainedHandler(authCtx)
		return convertToSSHPersmissions(authCtx, mwPerms, err)
	}

	// 设置公钥认证回调
	sshCfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		authCtx := middleware.NewAuthContext(conn.User(), conn.RemoteAddr(), "publickey")
		authCtx.Set("publickey", key)
		authCtx.ClientVersion = conn.ClientVersion()
		authCtx.SessionID = conn.SessionID()

		coreAuthFunc := func(currentCtx *middleware.AuthContext) (*middleware.Permissions, error) {
			return CorePublicKeyAuthenticator(s.config, currentCtx)
		}
		chainedHandler := s.authMiddlewareBuilder.Then(coreAuthFunc)
		mwPerms, err := chainedHandler(authCtx)
		return convertToSSHPersmissions(authCtx, mwPerms, err)
	}

	return s, nil
}

// Start 启动 SSH 服务器并开始监听连接.
func (s *SSHServer) Start() error {
	listenAddr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("无法监听地址 %s: %w", listenAddr, err)
	}
	s.listener = listener
	defer s.listener.Close()

	log.Printf("监听地址 %s, 端口 %d", s.config.Server.Host, s.config.Server.Port)
	for {
		tcpConn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil // 监听器已关闭, 正常退出
			}
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go s.handleConnection(tcpConn)
	}
}

// handleConnection 处理单个传入的 TCP 连接.
func (s *SSHServer) handleConnection(tcpConn net.Conn) {
	defer tcpConn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("处理连接时发生 panic: %v, 堆栈信息: %s", r, debug.Stack())
		}
	}()

	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.sshConfig)
	if err != nil {
		log.Printf("SSH 握手失败 (来自 %s): %v", tcpConn.RemoteAddr(), err)
		return
	}
	defer sshConn.Close()

	log.Printf("来自 %s 的新连接 (版本: %s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	go handleGlobalRequests(reqs)
	go s.dispatchChannels(sshConn, chans)

	sshConn.Wait()
	log.Printf("连接 %s 关闭", sshConn.RemoteAddr())
}

// convertToSSHPersmissions 是一个辅助函数, 用于处理中间件链的结果并转换为 ssh.Permissions.
func convertToSSHPersmissions(authCtx *middleware.AuthContext, mwPerms *middleware.Permissions, chainErr error) (*ssh.Permissions, error) {
	if chainErr != nil {
		return nil, chainErr
	}
	if authCtx.IsAborted() {
		if authCtx.Error() != nil {
			return nil, authCtx.Error()
		}
		return nil, fmt.Errorf("authentication aborted by middleware for user %s", authCtx.User)
	}
	if mwPerms == nil { // 理论上, 如果 chainErr 为 nil 且未中止, mwPerms 不应为 nil
		return nil, fmt.Errorf("authentication failed for user %s (no permissions returned)", authCtx.User)
	}

	// 总是初始化 Extensions, 即使它是空的, 以匹配某些库可能期望非nil map的行为.
	sshPerms := &ssh.Permissions{
		Extensions: make(map[string]string),
	}
	if mwPerms.SSHPAExtensions != nil {
		for k, v := range mwPerms.SSHPAExtensions { // 复制内容
			sshPerms.Extensions[k] = v
		}
	}
	return sshPerms, nil
}
