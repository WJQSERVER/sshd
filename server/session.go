package server

import (
	"encoding/binary"
	"log"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/WJQSERVER-STUDIO/go-utils/copyb"
	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

const defaultShell = "sh"

// sessionContext 封装了一个会话所需的上下文信息.
type sessionContext struct {
	server  *SSHServer
	sshConn *ssh.ServerConn
	channel ssh.Channel
	ptyFile *os.File
	ttyFile *os.File
	// wg 用于同步会话的生命周期, 确保父 goroutine 不会过早退出.
	wg sync.WaitGroup
}

// dispatchChannels 接收所有通道请求, 并根据类型分发给相应的处理器.
func (s *SSHServer) dispatchChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go s.handleChannel(sshConn, newChannel)
	}
}

// handleChannel 是处理新 channel 的入口点.
func (s *SSHServer) handleChannel(sshConn *ssh.ServerConn, newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		log.Printf("拒绝未知的通道类型: %s", t)
		newChannel.Reject(ssh.UnknownChannelType, "未知通道类型")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("无法接受通道 (用户: %s): %v", sshConn.User(), err)
		return
	}

	session := &sessionContext{
		server:  s,
		channel: channel,
		sshConn: sshConn,
	}
	defer session.close()

	for req := range requests {
		ok := false
		switch req.Type {
		case "exec":
			// exec 是一个一次性任务, 其 goroutine 会自行管理生命周期.
			session.handleExec(req)
			if req.WantReply {
				req.Reply(true, nil)
			}
			return // 此 channel 的使命完成, 等待 defer close.
		case "shell":
			if session.ptyFile != nil {
				ok = true
				// shell 是一个持续性任务, 我们需要等待它结束.
				session.handleShell()
				return
			}
		case "subsystem":
			if s.config.Server.SftpEnabled && string(req.Payload[4:]) == "sftp" {
				ok = true
				session.handleSftp()
				return
			}
		case "pty-req":
			ok = session.handlePtyReq(req)
		case "window-change":
			session.handleWindowChange(req)
			continue
		case "env":
			ok = true
		default:
			log.Printf("在会话中忽略未知请求类型: %s", req.Type)
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

// close 清理会话所有相关的资源.
func (s *sessionContext) close() {
	s.channel.Close()
	if s.ttyFile != nil {
		s.ttyFile.Close()
	}
	if s.ptyFile != nil {
		s.ptyFile.Close()
	}
	log.Printf("会话通道已关闭 (用户: %s)", s.sshConn.User())
}

// getUserInfo 是一个辅助方法.
func (s *sessionContext) getUserInfo() (homeDir, sysUsername, uidStr, gidStr string, ok bool) {
	perms := s.sshConn.Permissions
	if perms == nil || perms.Extensions["systemUserHome"] == "" {
		return "", "", "", "", false
	}
	homeDir = perms.Extensions["systemUserHome"]
	sysUsername = perms.Extensions["systemUsername"]
	if sysUsername == "" {
		sysUsername = s.sshConn.User()
	}
	uidStr = perms.Extensions["systemUserUID"]
	gidStr = perms.Extensions["systemUserGID"]
	return homeDir, sysUsername, uidStr, gidStr, true
}

// handleExec 正确地处理 "exec" 请求.
func (s *sessionContext) handleExec(req *ssh.Request) {
	homeDir, sysUsername, uidStr, gidStr, ok := s.getUserInfo()
	if !ok {
		return
	}

	command := string(req.Payload[4:])
	log.Printf("用户 '%s' 执行命令: %s", sysUsername, command)
	cmd := createCommand(defaultShell, command, homeDir, sysUsername, uidStr, gidStr)

	// 使用 CombinedOutput, 它会等待命令完成, 并返回 stdout 和 stderr 的合并输出.
	// 这样做更简单, 且能保证命令执行完毕.
	output, err := cmd.CombinedOutput()

	// 将命令的完整输出一次性写入 channel.
	if len(output) > 0 {
		s.channel.Write(output)
	}

	exitStatus := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitStatus = exitErr.ExitCode()
		} else {
			// 如果是启动错误等, 也认为是失败.
			log.Printf("执行命令时发生错误 (用户: %s): %v", sysUsername, err)
			exitStatus = 1
		}
	}

	log.Printf("命令执行完成 (用户: %s, 退出码: %d)", sysUsername, exitStatus)

	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(exitStatus))
	s.channel.SendRequest("exit-status", false, payload)
}

// handleShell 处理 "shell" 请求.
func (s *sessionContext) handleShell() {
	homeDir, sysUsername, uidStr, gidStr, ok := s.getUserInfo()
	if !ok {
		return
	}

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = defaultShell
	}

	log.Printf("用户 '%s' 启动 shell: %s", sysUsername, shell)
	cmd := createCommand(shell, "", homeDir, sysUsername, uidStr, gidStr)

	if err := PtyRun(cmd, s.ttyFile); err != nil {
		log.Printf("启动 pty shell 失败 (用户: %s): %v", sysUsername, err)
		return
	}

	// --- 核心修复: 使用 WaitGroup 来同步 I/O goroutine ---
	var wg sync.WaitGroup
	wg.Add(2)

	// 从 PTY 拷贝到 SSH channel
	go func() {
		defer wg.Done()
		copyb.Copy(s.channel, s.ptyFile)
	}()

	// 从 SSH channel 拷贝到 PTY
	go func() {
		defer wg.Done()
		copyb.Copy(s.ptyFile, s.channel)
	}()

	// 等待 shell 进程结束
	cmd.Wait()

	// shell 结束后, 主动关闭 ptyFile 和 channel 来终止 I/O goroutine.
	// 注意: s.close() 会在 handleChannel 的 defer 中被调用,
	// 但在这里提前关闭可以更快地终止 io.Copy.
	s.ptyFile.Close()
	s.channel.Close()

	// 等待 I/O goroutine 确实完成.
	wg.Wait()
}

// handleSftp 处理 "sftp" 请求.
func (s *sessionContext) handleSftp() {
	homeDir, sysUsername, _, _, ok := s.getUserInfo()
	if !ok {
		return
	}
	s.server.startSftp(s.channel, homeDir, sysUsername)
}

// handlePtyReq 处理 "pty-req" 请求.
func (s *sessionContext) handlePtyReq(req *ssh.Request) bool {
	if s.ptyFile != nil {
		log.Printf("警告: 用户 '%s' 重复请求 PTY", s.sshConn.User())
		return false
	}
	var err error
	s.ptyFile, s.ttyFile, err = pty.Open()
	if err != nil {
		log.Printf("无法为用户 '%s' 启动 pty: %v", s.sshConn.User(), err)
		return false
	}
	termLen := req.Payload[3]
	w, h := parseDims(req.Payload[termLen+4:])
	SetWindowSize(s.ptyFile.Fd(), w, h)
	log.Printf("PTY 请求成功 (用户: %s, 终端: %s, 尺寸: %dx%d)", s.sshConn.User(), string(req.Payload[4:termLen+4]), w, h)
	return true
}

// handleWindowChange 处理 "window-change" 请求.
func (s *sessionContext) handleWindowChange(req *ssh.Request) {
	if s.ptyFile == nil {
		return
	}
	w, h := parseDims(req.Payload)
	SetWindowSize(s.ptyFile.Fd(), w, h)
}

// createCommand 是一个辅助函数.
func createCommand(shellCmd, command, homeDir, sysUsername, uidStr, gidStr string) *exec.Cmd {
	var cmd *exec.Cmd
	if command != "" {
		cmd = exec.Command(shellCmd, "-c", command)
	} else {
		cmd = exec.Command(shellCmd)
	}
	cmd.Dir = homeDir
	cmd.Env = []string{"TERM=xterm", "HOME=" + homeDir}

	uid, errUid := strconv.ParseUint(uidStr, 10, 32)
	gid, errGid := strconv.ParseUint(gidStr, 10, 32)

	if errUid == nil && errGid == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		}
	} else {
		log.Printf("警告: 无法解析 UID/GID, 命令将以 SSHD 进程用户身份运行 (用户: %s)", sysUsername)
	}
	return cmd
}
