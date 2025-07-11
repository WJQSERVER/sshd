package server

import (
	"errors"
	"io"
	"log"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// startSftp 启动 SFTP 子系统.
func (s *SSHServer) startSftp(channel ssh.Channel, userHome, requestingUser string) {
	serverOptions := []sftp.ServerOption{
		sftp.WithServerWorkingDirectory(userHome),
	}
	if s.config.Server.SftpReadonly {
		serverOptions = append(serverOptions, sftp.ReadOnly())
	}

	server, err := sftp.NewServer(channel, serverOptions...)
	if err != nil {
		log.Printf("为用户 '%s' 启动 SFTP 服务器失败: %v", requestingUser, err)
		return
	}

	if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("SFTP 服务器 (用户: '%s') 运行出错: %v", requestingUser, err)
	}
}
