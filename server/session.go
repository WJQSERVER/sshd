package server

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

const defaultShell = "sh"

// dispatchChannels 接收所有通道请求, 并根据类型分发给相应的处理器.
func (s *SSHServer) dispatchChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			go s.handleSession(sshConn, newChannel)
		default:
			log.Printf("拒绝未知的通道类型: %s", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("未知通道类型: %s", newChannel.ChannelType()))
		}
	}
}

// handleSession 处理一个 "session" 通道.
func (s *SSHServer) handleSession(sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	perms := sshConn.Permissions
	if perms == nil || perms.Extensions["systemUserHome"] == "" {
		log.Printf("拒绝会话, 因为用户 '%s' 的权限或主目录信息不可用", sshConn.User())
		newChannel.Reject(ssh.ResourceShortage, "权限信息不可用")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("无法接受通道 (用户: %s): %v", sshConn.User(), err)
		return
	}

	session := &sessionContext{
		server:      s,
		sshConn:     sshConn,
		channel:     channel,
		homeDir:     perms.Extensions["systemUserHome"],
		sysUsername: perms.Extensions["systemUsername"],
		uidStr:      perms.Extensions["systemUserUID"],
		gidStr:      perms.Extensions["systemUserGID"],
	}
	if session.sysUsername == "" {
		session.sysUsername = sshConn.User()
	}

	go session.handleRequests(requests)
}

// sessionContext 封装了一个会话所需的上下文信息.
type sessionContext struct {
	server      *SSHServer
	sshConn     *ssh.ServerConn
	channel     ssh.Channel
	ptyFile     *os.File
	ttyFile     *os.File
	homeDir     string
	sysUsername string
	uidStr      string
	gidStr      string
}

// handleRequests 处理单个会话内的请求 (exec, shell, pty-req, etc.).
func (s *sessionContext) handleRequests(reqs <-chan *ssh.Request) {
	defer s.close() // 确保会话资源被清理

	for req := range reqs {
		var ok bool
		switch req.Type {
		case "exec":
			ok = s.handleExec(req)
		case "shell":
			ok = s.handleShell(req)
		case "pty-req":
			ok = s.handlePtyReq(req)
		case "window-change":
			s.handleWindowChange(req)
			continue // window-change 不需要回复
		case "subsystem":
			if s.server.config.Server.SftpEnabled && string(req.Payload[4:]) == "sftp" {
				ok = true
				go s.server.startSftp(s.channel, s.homeDir, s.sysUsername)
			}
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

// close 清理会话资源.
func (s *sessionContext) close() {
	s.channel.Close()
	if s.ttyFile != nil {
		s.ttyFile.Close()
	}
	if s.ptyFile != nil {
		s.ptyFile.Close()
	}
	log.Printf("会话通道已关闭 (用户: %s)", s.sysUsername)
}

func (s *sessionContext) createCommand(shellCmd, command string) *exec.Cmd {
	var cmd *exec.Cmd
	if command != "" {
		cmd = exec.Command(shellCmd, "-c", command)
	} else {
		cmd = exec.Command(shellCmd)
	}
	cmd.Dir = s.homeDir
	cmd.Env = []string{"TERM=xterm", "HOME=" + s.homeDir}

	uid, errUid := strconv.ParseUint(s.uidStr, 10, 32)
	gid, errGid := strconv.ParseUint(s.gidStr, 10, 32)

	if errUid == nil && errGid == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		}
	} else {
		log.Printf("警告: 无法解析 UID/GID, 命令将以 SSHD 进程用户身份运行 (用户: %s)", s.sysUsername)
	}
	return cmd
}

func (s *sessionContext) handleExec(req *ssh.Request) bool {
	command := string(req.Payload[4:])
	log.Printf("用户 '%s' 执行命令: %s", s.sysUsername, command)

	cmd := s.createCommand(defaultShell, command)
	cmd.Stdout = s.channel
	cmd.Stderr = s.channel
	cmd.Stdin = s.channel

	if err := cmd.Start(); err != nil {
		log.Printf("无法启动 exec 命令 (用户: %s): %v", s.sysUsername, err)
		return false
	}

	go func() {
		cmd.Wait()
		s.channel.Close() // 命令结束, 关闭通道
	}()

	return true
}

func (s *sessionContext) handleShell(req *ssh.Request) bool {
	if s.ptyFile == nil {
		log.Printf("用户 '%s' 在没有 PTY 的情况下请求 shell", s.sysUsername)
		return false // 在没有 PTY 的情况下不允许 shell
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = defaultShell
	}

	log.Printf("用户 '%s' 启动 shell: %s", s.sysUsername, shell)
	cmd := s.createCommand(shell, "")

	if err := PtyRun(cmd, s.ttyFile); err != nil {
		log.Printf("启动 pty shell 失败 (用户: %s): %v", s.sysUsername, err)
		return false
	}

	var once sync.Once
	closeOnce := func() { s.channel.Close() }

	go func() {
		io.Copy(s.channel, s.ptyFile)
		once.Do(closeOnce)
	}()
	go func() {
		io.Copy(s.ptyFile, s.channel)
		once.Do(closeOnce)
	}()

	return len(req.Payload) == 0
}

func (s *sessionContext) handlePtyReq(req *ssh.Request) bool {
	if s.ptyFile != nil {
		log.Printf("警告: 用户 '%s' 重复请求 PTY", s.sysUsername)
		return false // 不允许重复的 pty-req
	}

	var ptyErr error
	s.ptyFile, s.ttyFile, ptyErr = pty.Open()
	if ptyErr != nil {
		log.Printf("无法为用户 '%s' 启动 pty: %v", s.sysUsername, ptyErr)
		return false
	}

	termLen := req.Payload[3]
	w, h := parseDims(req.Payload[termLen+4:])
	SetWindowSize(s.ptyFile.Fd(), w, h)
	log.Printf("PTY 请求成功 (用户: %s, 终端: %s, 尺寸: %dx%d)", s.sysUsername, string(req.Payload[4:termLen+4]), w, h)
	return true
}

func (s *sessionContext) handleWindowChange(req *ssh.Request) {
	if s.ptyFile == nil {
		return // 如果没有 pty, 则忽略
	}
	w, h := parseDims(req.Payload)
	SetWindowSize(s.ptyFile.Fd(), w, h)
}
