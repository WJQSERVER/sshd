package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime/debug"
	// "strconv" // No longer used
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// 配置变量
var (
	defaultShell = "sh"
)

type SSHServer struct {
	Port         int
	Address      string
	Server           *ssh.ServerConfig
	// HostKey      []byte // Removed as it's unused; ServerConfig holds the host keys
	EnableSftp       bool
	ReadOnlySftp     bool
	// UserHomesBaseDir string // Removed: System user homes are now used directly
}

func (s *SSHServer) Start() {
	// 配置好 ServerConfig 后，可以接受连接。
	listenAddr := fmt.Sprintf("%s:%d", s.Address, s.Port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("无法监听地址 %s: %v", listenAddr, err) // 错误信息更详细
		return                                   // 启动失败直接返回，避免后续 panic
	}
	defer listener.Close() // 确保 listener 关闭

	// 接受所有连接
	log.Printf("监听地址 %s, 端口 %d", s.Address, s.Port)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			// 接受连接失败，打印错误信息，但继续监听，保证服务器稳定性
			log.Printf("接受连接失败: %v", err)
			continue
		}

		// 使用 goroutine 处理每个连接，避免阻塞主循环
		go func() {
			defer tcpConn.Close() // 确保 tcpConn 关闭
			// 捕获 panic，防止单个连接处理错误导致整个服务器崩溃
			defer func() {
				if r := recover(); r != nil {
					log.Printf("处理连接时发生 panic: %v, 堆栈信息: %s", r, debug.Stack())
				}
			}()

			err := s.handleConn(tcpConn) // 将连接处理逻辑提取到单独的函数
			if err != nil {
				log.Printf("处理连接时发生错误: %v", err)
			}
		}()
	}
}

func (s *SSHServer) handleConn(tcpConn net.Conn) error {
	// 在使用之前，必须对传入的 net.Conn 进行握手。
	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.Server)
	if err != nil {
		log.Printf("SSH 握手失败: %v", err)
		return fmt.Errorf("ssh handshake failed: %w", err) // 返回错误，方便上层处理
	}
	defer sshConn.Close() // 确保 sshConn 关闭

	// 检查远程地址
	log.Printf("来自 %s 的新连接 (版本: %s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// 处理传入的全局请求 (例如 keep-alive)
	go s.handleGlobalRequests(reqs) // 将全局请求处理提取到单独的函数
	// 接受所有通道请求 (例如 session, sftp)
	go s.handleChannels(sshConn, chans) // Pass sshConn here

	// 等待连接关闭，或者可以添加超时机制
	sshConn.Wait()
	log.Printf("连接 %s 关闭", sshConn.RemoteAddr())
	return nil
}

func (s *SSHServer) handleGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("接收到的全局请求: 类型 = %s, 想要回复 = %v, 数据 = %v", req.Type, req.WantReply, req.Payload)
		// 这里可以根据 req.Type 处理全局请求，例如 "tcpip-forward", "cancel-tcpip-forward" 等
		// 对于不认识的请求，应该回复 false (拒绝) 如果 req.WantReply 为 true
		if req.WantReply {
			req.Reply(false, nil) // 默认拒绝未知全局请求
		}
	}
}

// PtyRun 启动一个伪终端 tty os.File，并将其分配给 c.Stdin, c.Stdout,
// 和 c.Stderr，调用 c.Start，并返回 tty 对应的 pty 的 File。
func PtyRun(c *exec.Cmd, tty *os.File) (err error) {
	defer tty.Close() // 确保 tty 在函数退出时关闭
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	err = c.Start()
	if err != nil {
		return fmt.Errorf("pty run cmd start failed: %w", err) // 返回更详细的错误信息
	}
	return nil
}

func (s *SSHServer) handleChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	// Get system user details stored during authentication
	perms := sshConn.Permissions // Corrected: Permissions is a field, not a method
	if perms == nil {
		// This case should ideally not be reached if authentication was successful
		// and permissions were set.
		log.Printf("错误: 用户 '%s' 的权限信息为空。拒绝会话。", sshConn.User())
		// Reject all incoming channels on this connection
		for newChannel := range chans {
			newChannel.Reject(ssh.ResourceShortage, "权限信息不可用")
		}
		return
	}
	sysUserHome := perms.Extensions["systemUserHome"]
	sysUserUID := perms.Extensions["systemUserUID"] // Will be used for impersonation later
	sysUserGID := perms.Extensions["systemUserGID"] // Will be used for impersonation later
	sysUsername := perms.Extensions["systemUsername"]

	if sysUserHome == "" {
		log.Printf("错误: 系统用户 '%s' 的主目录信息未在权限中找到。拒绝会话。", sshConn.User())
		// It's unlikely to reach here if auth succeeded and set these, but good to check.
		// We cannot proceed without a home directory for the user.
		// For loop below will handle rejecting channels if this state is reached.
	}
	if sysUsername == "" { // If username is missing, use the one from connection
		sysUsername = sshConn.User()
	}

	log.Printf("为系统用户 '%s' (UID: %s, GID: %s, Home: %s) 处理通道请求", sysUsername, sysUserUID, sysUserGID, sysUserHome)

	// 处理传入的 Channel 通道。
	for newChannel := range chans {
		if sysUserHome == "" { // Check again inside loop for safety before processing each channel
			log.Printf("拒绝通道请求，因为用户 '%s' 的主目录未知。", sysUsername)
			newChannel.Reject(ssh.ResourceShortage, "用户主目录信息不可用")
			continue
		}

		if t := newChannel.ChannelType(); t != "session" {
			err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("未知通道类型: %s", t))
			if err != nil {
				log.Printf("拒绝未知通道类型失败: %v", err)
				continue
			}
			log.Printf("拒绝未知通道类型: %s (用户: %s)", t, sysUsername)
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("无法接受通道 (用户: %s): %v", sysUsername, err)
			continue
		}

		// userHomePath is now sysUserHome, which is the actual system home directory.
		// No need to create it here, as it should exist for a system user.
		// If it doesn't exist, commands will likely fail, which is expected OS behavior.
		userHomePath := sysUserHome

		log.Printf("为用户 '%s' 创建 pty (将使用主目录: %s)", sysUsername, userHomePath)
		// 创建新的 pty
		f, tty, err := pty.Open()
		if err != nil {
			log.Printf("无法启动 pty: %v", err)
			channel.Close() // 及时关闭 channel
			continue
		}

		var shell string
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = defaultShell
		}

		// 会话有带外请求，例如 "shell"、"pty-req" 和 "env"
		go func(in <-chan *ssh.Request, userSpecificHome string, requestingUser string) { // Pass userHomePath and user
			defer func() {
				// 确保 channel 和 pty 相关的文件描述符在会话结束时关闭
				channel.Close()
				tty.Close() // 确保 tty 也关闭
				f.Close()   // 确保 f 也关闭
				log.Printf("会话通道已关闭 (用户: %s)", requestingUser) // requestingUser is passed as sysUsername
			}()
			defer func() { // 捕获 request 处理中的 panic
				if r := recover(); r != nil {
					log.Printf("处理 channel request 时发生 panic: %v, 堆栈信息: %s", r, debug.Stack())
				}
			}()

			for req := range in {
				ok := false
				switch req.Type {
				case "exec":
					ok = true
					command := string(req.Payload[4:])
					log.Printf("用户 '%s' 在目录 '%s' 执行命令: %s", requestingUser, userSpecificHome, command)
					cmd := exec.Command(shell, "-c", command) // 修复参数传递问题，使用 "-c" 执行命令
					cmd.Dir = userSpecificHome // Set working directory for the command

					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Stdin = channel

					err := cmd.Start()
					if err != nil {
						log.Printf("无法启动命令 '%s' (用户: %s, 目录: %s): %v", command, requestingUser, userSpecificHome, err)
						continue // 继续处理其他请求，或者考虑关闭 channel
					}
					// 拆除会话
					go func() {
						err := cmd.Wait() // 使用 Wait 获取命令执行结果和错误
						if err != nil {
							log.Printf("命令执行失败: %v", err)
						}
						// channel.Close() //  在 defer 中统一关闭
						log.Printf("命令执行完成, 会话准备关闭")
					}()
				case "shell":
					log.Printf("用户 '%s' 在目录 '%s' 启动 shell: %s", requestingUser, userSpecificHome, shell)
					cmd := exec.Command(shell)
					cmd.Dir = userSpecificHome // Set working directory for the shell
					cmd.Env = []string{"TERM=xterm", "HOME=" + userSpecificHome} // Set HOME environment variable
					err := PtyRun(cmd, tty)
					if err != nil {
						log.Printf("启动 pty shell '%s' 失败 (用户: %s, 目录: %s): %v", shell, requestingUser, userSpecificHome, err)
						continue // 继续处理其他请求，或者考虑关闭 channel
					}

					// 拆除会话
					var once sync.Once
					closeOnce := func() {
						// channel.Close() // 在 defer 中统一关闭
						log.Printf("shell 会话关闭 (once)")
					}

					// 将会话与 bash 进行双向管道
					go func() {
						_, err := io.Copy(channel, f)                                                // 从 pty (f) 读取并写入 channel (ssh client)
						if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) { // 忽略 EOF 和 net.ErrClosed 错误
							log.Printf("io.Copy(channel, f) 错误: %v", err)
						}
						once.Do(closeOnce)
					}()

					go func() {
						_, err := io.Copy(f, channel)                                                // 从 channel (ssh client) 读取并写入 pty (f)
						if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) { // 忽略 EOF 和 net.ErrClosed 错误
							log.Printf("io.Copy(f, channel) 错误: %v", err)
						}
						once.Do(closeOnce)
					}()

					// 我们不接受任何命令 (Payload)，
					// 仅接受默认 shell。
					if len(req.Payload) == 0 {
						ok = true
					}
				case "pty-req":
					// 在这里响应 'ok' 将让客户端
					// 知道我们已经准备好 pty 进行输入
					ok = true
					termLen := req.Payload[3]
					termEnv := string(req.Payload[4 : termLen+4])
					w, h := parseDims(req.Payload[termLen+4:])
					SetWindowSize(f.Fd(), w, h)
					log.Printf("pty-req 请求, 终端类型 = '%s', 窗口大小 = %dx%d", termEnv, w, h)
				case "window-change":
					w, h := parseDims(req.Payload)
					SetWindowSize(f.Fd(), w, h)
					log.Printf("窗口大小调整请求, 窗口大小 = %dx%d", w, h)
					continue // 不需要响应，因为 ssh 协议中 window-change 不需要回复
				case "subsystem":
					subsystemName := string(req.Payload[4:])
					log.Printf("子系统请求: %s", subsystemName)
					if subsystemName == "sftp" {
						if s.EnableSftp {
							ok = true
							// Pass userSpecificHome to startSftp
							go s.startSftp(channel, userSpecificHome, requestingUser)
						} else {
							log.Printf("SFTP 子系统被禁用 (用户: %s)", requestingUser)
						}
					} else {
						log.Printf("未知的子系统请求 '%s' (用户: %s)", subsystemName, requestingUser)
					}
				}

				if req.WantReply {
					if !ok {
						log.Printf("拒绝类型为 '%s' 的请求 (用户: %s)", req.Type, requestingUser)
					}
					req.Reply(ok, nil)
				}
			}
		}(requests, userHomePath, sysUsername) // Pass userHomePath (which is sysUserHome) and sysUsername
	}
}

func (s *SSHServer) startSftp(channel ssh.Channel, userHome string, requestingUser string) { // requestingUser is sysUsername
	log.Printf("为用户 '%s' 启动 SFTP 子系统。建议的家目录: '%s'", requestingUser, userHome)
	log.Printf("注意: 当前 SFTP 实现未 chroot 用户到家目录。操作将相对于 SSHD 进程的当前工作目录进行。用户需要手动导航到 '%s'。", userHome)


	// Ensure userHome directory exists (it should have been created by handleChannels)
	if _, err := os.Stat(userHome); os.IsNotExist(err) {
		log.Printf("SFTP: 用户 '%s' 的家目录 '%s' 不存在。这可能导致 SFTP 操作问题。", requestingUser, userHome)
		// We could attempt to create it here again, but it's better handled centrally.
	}


	serverOptions := []sftp.ServerOption{
		// sftp.WithDebug(os.Stderr), //  Enable SFTP debugging output
	}

	if s.ReadOnlySftp {
		serverOptions = append(serverOptions, sftp.ReadOnly())
		log.Printf("SFTP 服务器为用户 '%s' 以只读模式运行", requestingUser)
	} else {
		log.Printf("SFTP 服务器为用户 '%s' 以读写模式运行", requestingUser)
	}

	// Create a new SFTP server for this channel.
	// By default, it serves files from the current working directory of the SSHD process.
	// Implementing a true chroot per user with pkg/sftp requires custom sftp.Handlers.
	server, err := sftp.NewServer(
		channel,
		serverOptions...,
	)
	if err != nil {
		log.Printf("为用户 '%s' 启动 SFTP 服务器失败: %v", requestingUser, err)
		return
	}

	log.Printf("SFTP server started for user %s. Client needs to 'cd %s' or use absolute paths from process CWD.", requestingUser, userHome)

	if err := server.Serve(); err != nil {
		if errors.Is(err, io.EOF) {
			log.Printf("SFTP 客户端 (用户: '%s') 退出会话。", requestingUser)
		} else {
			log.Printf("SFTP 服务器 (用户: '%s') 运行出错: %v", requestingUser, err)
		}
	} else {
		log.Printf("SFTP 会话 (用户: '%s') 正常结束。", requestingUser)
	}
	// server.Close() is typically handled by Serve() returning or if an error occurs before Serve()
	// but it's good practice if Serve() might not clean up fully on all paths.
	// However, sftp.Server.Serve() blocks until client disconnects or error.
	// Closing the channel (which happens in the calling goroutine's defer) should signal the server.
	log.Printf("SFTP 子系统 (用户: '%s') 已关闭", requestingUser)
}

// parseDims 从提供的缓冲区提取两个 uint32，表示窗口宽度和高度。
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// WindowSize 存储终端的高度和宽度。
type WindowSize struct {
	Height uint16
	Width  uint16
}

// SetWindowSize 设置给定 pty 的大小。
func SetWindowSize(fd uintptr, w, h uint32) {
	log.Printf("调整窗口大小为 %dx%d", w, h)
	ws := &WindowSize{Width: uint16(w), Height: uint16(h)}
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
	if err != 0 {
		log.Printf("设置窗口大小失败: %v", err) // 记录设置窗口大小失败的错误
	}
}
