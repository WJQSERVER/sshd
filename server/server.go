package server

import (
	"errors"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"sshd/config"

	"golang.org/x/crypto/ssh"
)

// SSHServer 定义了 SSH 服务器的结构.
type SSHServer struct {
	config    *config.Config
	listener  net.Listener
	sshConfig *ssh.ServerConfig
}

// NewServer 是 SSHServer 的构造函数, 封装了所有初始化逻辑.
func NewServer(cfg *config.Config) (*SSHServer, error) {
	signer, err := loadOrCreateHostKey(cfg)
	if err != nil {
		return nil, fmt.Errorf("加载或创建主机密钥失败: %w", err)
	}

	sshCfg := &ssh.ServerConfig{
		PasswordCallback:  createPasswordCallback(cfg),
		PublicKeyCallback: createPublicKeyCallback(cfg),
	}
	sshCfg.AddHostKey(signer)

	return &SSHServer{
		config:    cfg,
		sshConfig: sshCfg,
	}, nil
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
