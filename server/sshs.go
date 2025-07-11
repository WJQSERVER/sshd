//go:build linux

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
	"strconv" // 用于 ParseUint
	"sync"
	"syscall"
	"unsafe"

	// "os/user" // 在此文件中不再需要, 因为移除了补充组逻辑
	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// defaultShell 定义了在无法从环境获取时的默认 shell.
var (
	defaultShell = "sh"
)

// SSHServer 定义了 SSH 服务器的结构.
type SSHServer struct {
	Port    int               // 服务器监听的端口
	Address string            // 服务器监听的地址
	Server  *ssh.ServerConfig // SSH 服务器配置
	// HostKey 字段已移除, 因其未被使用; ServerConfig 通过 AddHostKey 保存主机密钥.
	EnableSftp   bool // 是否启用 SFTP
	ReadOnlySftp bool // SFTP 是否为只读模式
	// UserHomesBaseDir 字段已移除: 现在直接使用系统用户的主目录.
}

// Start 启动 SSH 服务器并开始监听连接.
func (s *SSHServer) Start() {
	// 配置好 ServerConfig 后, 即可接受连接.
	listenAddr := fmt.Sprintf("%s:%d", s.Address, s.Port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("无法监听地址 %s: %v", listenAddr, err) // 使错误信息更详细
		return                                       // 启动失败则直接返回, 避免后续 panic
	}
	defer listener.Close() // 确保 listener 被关闭

	// 接受所有传入连接
	log.Printf("监听地址 %s, 端口 %d", s.Address, s.Port)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			// 接受连接失败, 打印错误信息但继续监听, 以保证服务器稳定性
			log.Printf("接受连接失败: %v", err)
			continue
		}

		// 为每个连接使用一个 goroutine 进行处理, 避免阻塞主循环
		go func() {
			defer tcpConn.Close() // 确保 tcpConn 被关闭
			// 捕获 panic, 防止单个连接处理错误导致整个服务器崩溃
			defer func() {
				if r := recover(); r != nil {
					log.Printf("处理连接时发生 panic: %v, 堆栈信息: %s", r, debug.Stack())
				}
			}()

			err := s.handleConn(tcpConn) // 将连接处理逻辑提取到单独的函数中
			if err != nil {
				log.Printf("处理连接时发生错误: %v", err)
			}
		}()
	}
}

// handleConn 处理单个传入的 TCP 连接.
func (s *SSHServer) handleConn(tcpConn net.Conn) error {
	// 在使用传入的 net.Conn 之前, 必须进行 SSH 握手.
	sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.Server)
	if err != nil {
		log.Printf("SSH 握手失败: %v", err)
		return fmt.Errorf("ssh handshake failed: %w", err) // 返回错误, 以便上层进行处理
	}
	defer sshConn.Close() // 确保 sshConn 被关闭

	// 记录远程地址和客户端版本
	log.Printf("来自 %s 的新连接 (版本: %s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// 处理传入的全局请求 (例如 keep-alive)
	go s.handleGlobalRequests(reqs) // 将全局请求处理提取到单独的函数中
	// 接受所有通道请求 (例如 session, sftp)
	go s.handleChannels(sshConn, chans) // 在此传递 sshConn

	// 等待连接关闭, 或可以添加超时机制
	sshConn.Wait()
	log.Printf("连接 %s 关闭", sshConn.RemoteAddr())
	return nil
}

// handleGlobalRequests 处理 SSH 全局请求.
func (s *SSHServer) handleGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("接收到的全局请求: 类型 = %s, 想要回复 = %v, 数据 = %v", req.Type, req.WantReply, req.Payload)
		// 这里可以根据 req.Type 处理全局请求, 例如 "tcpip-forward", "cancel-tcpip-forward" 等
		// 对于无法识别的请求, 如果 req.WantReply 为 true, 则应回复 false (拒绝)
		if req.WantReply {
			req.Reply(false, nil) // 默认拒绝未知的全局请求
		}
	}
}

// PtyRun 启动一个伪终端 (pty) os.File, 将其分配给 c.Stdin, c.Stdout,
// 和 c.Stderr, 调用 c.Start, 并返回与 tty 对应的 pty 的 File.
func PtyRun(c *exec.Cmd, tty *os.File) (err error) {
	defer tty.Close() // 确保 tty 在函数退出时关闭
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true, // 设置控制终端
		Setsid:  true, // 创建新的会话ID
	}
	err = c.Start()
	if err != nil {
		return fmt.Errorf("pty run cmd start failed: %w", err) // 返回更详细的错误信息
	}
	return nil
}

// handleChannels 处理 SSH 通道请求, 如会话和子系统.
func (s *SSHServer) handleChannels(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	// 获取认证期间存储的系统用户详细信息
	perms := sshConn.Permissions // Permissions 是一个字段, 而不是方法
	if perms == nil {
		// 理想情况下, 如果认证成功并设置了权限, 则不应到达此情况
		log.Printf("错误: 用户 '%s' 的权限信息为空。拒绝会话。", sshConn.User())
		// 拒绝此连接上的所有传入通道
		for newChannel := range chans {
			newChannel.Reject(ssh.ResourceShortage, "权限信息不可用")
		}
		return
	}
	sysUserHome := perms.Extensions["systemUserHome"]
	sysUserUID := perms.Extensions["systemUserUID"] // 稍后用于用户模拟
	sysUserGID := perms.Extensions["systemUserGID"] // 稍后用于用户模拟
	sysUsername := perms.Extensions["systemUsername"]

	if sysUserHome == "" {
		log.Printf("错误: 系统用户 '%s' 的主目录信息未在权限中找到。拒绝会话。", sshConn.User())
		// 如果认证成功并设置了这些信息, 则不太可能到达此处, 但最好进行检查.
		// 如果没有用户主目录, 则无法继续.
		// 下面的 for 循环将处理在此状态下拒绝通道的情况.
	}
	if sysUsername == "" { // 如果用户名缺失, 则使用连接中的用户名
		sysUsername = sshConn.User()
	}

	log.Printf("为系统用户 '%s' (UID: %s, GID: %s, Home: %s) 处理通道请求", sysUsername, sysUserUID, sysUserGID, sysUserHome)

	// 处理传入的 Channel 通道.
	for newChannel := range chans {
		if sysUserHome == "" { // 在处理每个通道之前, 在循环内部再次检查以确保安全
			log.Printf("拒绝通道请求, 因为用户 '%s' 的主目录未知。", sysUsername)
			newChannel.Reject(ssh.ResourceShortage, "用户主目录信息不可用")
			continue
		}

		if t := newChannel.ChannelType(); t != "session" { // 目前只支持 "session" 类型的通道
			err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("未知通道类型: %s", t))
			if err != nil {
				log.Printf("拒绝未知通道类型失败: %v", err) // 记录拒绝失败的错误
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

		// userHomePath 现在是 sysUserHome, 即实际的系统主目录.
		// 此处无需创建它, 因为它应该存在于系统用户中.
		// 如果它不存在, 命令可能会失败, 这是预期的操作系统行为.
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
		shell = os.Getenv("SHELL") // 尝试从环境变量获取 shell
		if shell == "" {
			shell = defaultShell // 如果未找到, 则使用默认 shell
		}

		// 会话具有带外请求, 例如 "shell", "pty-req" 和 "env"
		go func(in <-chan *ssh.Request, userSpecificHome string, requestingUser string, uidStr string, gidStr string) { // 传递 UID 和 GID 字符串
			defer func() {
				// 确保在会话结束时关闭 channel 和与 pty 相关的文件描述符
				channel.Close()
				tty.Close()                                    // 确保 tty 也被关闭
				f.Close()                                      // 确保 f 也被关闭
				log.Printf("会话通道已关闭 (用户: %s)", requestingUser) // requestingUser 作为 sysUsername 传递
			}()
			defer func() { // 捕获请求处理中的 panic
				if r := recover(); r != nil {
					log.Printf("处理 channel request 时发生 panic: %v, 堆栈信息: %s", r, debug.Stack())
				}
			}()

			for req := range in {
				ok := false // 标记请求是否成功处理
				switch req.Type {
				case "exec": // 执行命令请求
					ok = true
					command := string(req.Payload[4:]) // 提取命令字符串
					log.Printf("用户 '%s' 在目录 '%s' 执行命令: %s", requestingUser, userSpecificHome, command)
					cmd := exec.Command(shell, "-c", command)
					cmd.Dir = userSpecificHome // 设置命令的工作目录

					// 尝试为命令设置用户凭据
					uid, errUid := strconv.ParseUint(uidStr, 10, 32) // 使用传递的 uidStr
					gid, errGid := strconv.ParseUint(gidStr, 10, 32) // 使用传递的 gidStr

					if errUid == nil && errGid == nil {
						if cmd.SysProcAttr == nil {
							cmd.SysProcAttr = &syscall.SysProcAttr{}
						}
						cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
						log.Printf("为命令 '%s' 设置主凭据 UID=%d, GID=%d (用户: %s)", command, uint32(uid), uint32(gid), requestingUser)
						// 由于在没有 CGo 的情况下, syscall.SysProcAttr 在 Go 版本/环境中不标准可用,
						// 目前省略了补充组设置 (SysProcAttr.Gids).
						// 如果需要, 未来的工作可能会通过更强大的解决方案重新引入此功能.
					} else {
						log.Printf("警告: 无法解析 UID (%s) 或 GID (%s) 为用户 '%s' 执行命令 '%s'. 命令将以 SSHD 进程用户身份运行. UidErr: %v, GidErr: %v",
							uidStr, gidStr, requestingUser, command, errUid, errGid)
						// 回退: 命令以 SSHD 进程用户 (root) 身份运行
					}

					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Stdin = channel

					err := cmd.Start()
					if err != nil {
						log.Printf("无法启动命令 '%s' (用户: %s, 目录: %s, UID: %s, GID: %s): %v",
							command, requestingUser, userSpecificHome, uidStr, gidStr, err) // 使用 uidStr, gidStr 记录日志
						continue
					}
					// 拆除会话
					go func() {
						err := cmd.Wait() // 使用 Wait 获取命令执行结果和错误
						if err != nil {
							log.Printf("命令执行失败: %v", err)
						}
						// channel.Close() // 在 defer 中统一关闭
						log.Printf("命令执行完成, 会话准备关闭")
					}()
				case "shell": // 启动 shell 请求
					log.Printf("用户 '%s' 在目录 '%s' 启动 shell: %s", requestingUser, userSpecificHome, shell)
					cmd := exec.Command(shell)
					cmd.Dir = userSpecificHome
					cmd.Env = []string{"TERM=xterm", "HOME=" + userSpecificHome} // 设置基本环境变量

					// 尝试为 shell 进程设置用户凭据
					uid, errUid := strconv.ParseUint(uidStr, 10, 32)
					gid, errGid := strconv.ParseUint(gidStr, 10, 32)

					if errUid == nil && errGid == nil {
						// 对于基于 PTY 的 shell, Setctty 和 Setsid 也很重要.
						// 在设置多个字段之前, 确保 SysProcAttr 已初始化.
						if cmd.SysProcAttr == nil {
							cmd.SysProcAttr = &syscall.SysProcAttr{}
						}
						cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
						log.Printf("为 shell '%s' 设置主凭据 UID=%d, GID=%d (用户: %s)", shell, uint32(uid), uint32(gid), requestingUser)
						// 目前省略了补充组设置 (SysProcAttr.Gids).
						// PtyRun 处理 Setctty 和 Setsid.
					} else {
						log.Printf("警告: 无法解析 UID (%s) 或 GID (%s) 为用户 '%s' 启动 shell '%s'. Shell 将以 SSHD 进程用户身份运行. UidErr: %v, GidErr: %v",
							uidStr, gidStr, requestingUser, shell, errUid, errGid)
						// 回退: shell 以 SSHD 进程用户 (root) 身份运行
					}

					err := PtyRun(cmd, tty) // PtyRun 也会设置 Setctty 和 Setsid
					if err != nil {
						log.Printf("启动 pty shell '%s' 失败 (用户: %s, 目录: %s, UID: %s, GID: %s): %v",
							shell, requestingUser, userSpecificHome, uidStr, gidStr, err)
						continue // 继续处理其他请求, 或考虑关闭 channel
					}

					// 拆除会话
					var once sync.Once
					closeOnce := func() {
						// channel.Close() // 在 defer 中统一关闭
						log.Printf("shell 会话关闭 (once)")
					}

					// 将会话与 pty 进行双向数据复制
					go func() {
						_, err := io.Copy(channel, f)                                                // 从 pty (f) 读取并写入 channel (ssh 客户端)
						if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) { // 忽略 EOF 和 net.ErrClosed 错误
							log.Printf("io.Copy(channel, f) 错误: %v", err)
						}
						once.Do(closeOnce)
					}()

					go func() {
						_, err := io.Copy(f, channel)                                                // 从 channel (ssh 客户端) 读取并写入 pty (f)
						if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) { // 忽略 EOF 和 net.ErrClosed 错误
							log.Printf("io.Copy(f, channel) 错误: %v", err)
						}
						once.Do(closeOnce)
					}()

					// 我们不接受任何命令 (Payload),
					// 仅接受默认 shell.
					if len(req.Payload) == 0 {
						ok = true
					}
				case "pty-req": // pty 请求 (分配伪终端)
					// 在此响应 'ok' 将使客户端
					// 知道我们已准备好 pty 以进行输入
					ok = true
					termLen := req.Payload[3]
					termEnv := string(req.Payload[4 : termLen+4]) // 终端环境变量 (例如 "xterm")
					w, h := parseDims(req.Payload[termLen+4:])    // 解析终端窗口尺寸
					SetWindowSize(f.Fd(), w, h)                   // 设置 pty 窗口大小
					log.Printf("pty-req 请求, 终端类型 = '%s', 窗口大小 = %dx%d", termEnv, w, h)
				case "window-change": // 窗口大小更改请求
					w, h := parseDims(req.Payload)
					SetWindowSize(f.Fd(), w, h)
					log.Printf("窗口大小调整请求, 窗口大小 = %dx%d", w, h)
					continue // 不需要响应, 因为 ssh 协议中的 window-change 不需要回复
				case "subsystem": // 子系统请求 (例如 sftp)
					subsystemName := string(req.Payload[4:])
					log.Printf("子系统请求: %s", subsystemName)
					if subsystemName == "sftp" {
						if s.EnableSftp {
							ok = true
							// 将 userSpecificHome 传递给 startSftp
							go s.startSftp(channel, userSpecificHome, requestingUser)
						} else {
							log.Printf("SFTP 子系统被禁用 (用户: %s)", requestingUser)
						}
					} else {
						log.Printf("未知的子系统请求 '%s' (用户: %s)", subsystemName, requestingUser)
					}
				}

				if req.WantReply { // 如果客户端期望回复
					if !ok {
						log.Printf("拒绝类型为 '%s' 的请求 (用户: %s)", req.Type, requestingUser)
					}
					req.Reply(ok, nil) // 回复请求处理结果
				}
			}
		}(requests, userHomePath, sysUsername, sysUserUID, sysUserGID) // 传递 UID 和 GID
	}
}

// startSftp 启动 SFTP 子系统.
func (s *SSHServer) startSftp(channel ssh.Channel, userHome string, requestingUser string) { // requestingUser 是 sysUsername
	log.Printf("为用户 '%s' 启动 SFTP 子系统。建议的主目录: '%s'", requestingUser, userHome)
	log.Printf("注意: 当前 SFTP 实现未将用户 chroot 到其主目录。操作将相对于 SSHD 进程的当前工作目录进行。用户需要手动导航到 '%s'。", userHome)

	// 确保 userHome 目录存在 (它应该已由 handleChannels 创建)
	if _, err := os.Stat(userHome); os.IsNotExist(err) {
		log.Printf("SFTP: 用户 '%s' 的主目录 '%s' 不存在。这可能导致 SFTP 操作问题。", requestingUser, userHome)
		// 我们可以在这里再次尝试创建它, 但最好集中处理.
	}

	serverOptions := []sftp.ServerOption{
		// sftp.WithDebug(os.Stderr), // 启用 SFTP 调试输出
	}

	if s.ReadOnlySftp {
		serverOptions = append(serverOptions, sftp.ReadOnly())
		log.Printf("SFTP 服务器为用户 '%s' 以只读模式运行", requestingUser)
	} else {
		log.Printf("SFTP 服务器为用户 '%s' 以读写模式运行", requestingUser)
	}

	// 为此通道创建一个新的 SFTP 服务器.
	// 默认情况下, 它从 SSHD 进程的当前工作目录提供文件.
	// 使用 pkg/sftp 为每个用户实现真正的 chroot 需要自定义 sftp.Handlers.
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
	// server.Close() 通常由 Serve() 返回或在 Serve() 之前发生错误时处理
	// 但如果 Serve() 可能无法在所有路径上完全清理, 则这是一个好习惯.
	// 但是, sftp.Server.Serve() 会阻塞, 直到客户端断开连接或发生错误.
	// 关闭通道 (这发生在调用 goroutine 的 defer 中) 应该向服务器发送信号.
	log.Printf("SFTP 子系统 (用户: '%s') 已关闭", requestingUser)
}

// parseDims 从提供的字节缓冲区中提取两个 uint32 值, 分别表示窗口的宽度和高度.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// WindowSize 存储终端的高度和宽度.
type WindowSize struct {
	Height uint16 // 终端高度
	Width  uint16 // 终端宽度
}

// SetWindowSize 设置给定 pty 的大小.
func SetWindowSize(fd uintptr, w, h uint32) {
	log.Printf("调整窗口大小为 %dx%d", w, h)
	ws := &WindowSize{Width: uint16(w), Height: uint16(h)}
	// 使用 syscall.SYS_IOCTL 和 syscall.TIOCSWINSZ 来设置窗口大小
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
	if err != 0 { // syscall 在出错时返回非零的 err
		log.Printf("设置窗口大小失败: %v", err) // 记录设置窗口大小失败的错误
	}
}
