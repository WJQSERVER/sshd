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
	"strconv"
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
	Server       *ssh.ServerConfig
	HostKey      []byte
	EnableSftp   bool
	ReadOnlySftp bool
}

func (s *SSHServer) Start() {
	// 配置好 ServerConfig 后，可以接受连接。
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(s.Port))
	if err != nil {
		log.Fatalf("无法监听端口 %d: %v", s.Port, err) // 错误信息更详细
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
	go s.handleChannels(chans)

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

func (s *SSHServer) handleChannels(chans <-chan ssh.NewChannel) {
	// 处理传入的 Channel 通道。
	for newChannel := range chans {
		// 通道有一个类型，取决于预期的应用层协议。
		// 在 shell 的情况下，类型是 "session"，可以使用 ServerShell 提供简单的终端接口。
		if t := newChannel.ChannelType(); t != "session" {
			err := newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("未知通道类型: %s", t))
			if err != nil {
				log.Printf("拒绝未知通道类型失败: %v", err)
				continue
			}
			log.Printf("拒绝未知通道类型: %s", t) // 添加日志
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("无法接受通道: %v", err)
			continue
		}

		// 为此通道分配一个终端
		log.Print("创建 pty...")
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
		go func(in <-chan *ssh.Request) {
			defer func() {
				// 确保 channel 和 pty 相关的文件描述符在会话结束时关闭
				channel.Close()
				tty.Close() // 确保 tty 也关闭
				f.Close()   // 确保 f 也关闭
				log.Printf("会话通道已关闭")
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
					log.Printf("执行命令: %s", command)
					cmd := exec.Command(shell, "-c", command) // 修复参数传递问题，使用 "-c" 执行命令

					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Stdin = channel

					err := cmd.Start()
					if err != nil {
						log.Printf("无法启动命令: %v", err)
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
					cmd := exec.Command(shell)
					cmd.Env = []string{"TERM=xterm"}
					err := PtyRun(cmd, tty)
					if err != nil {
						log.Printf("启动 pty shell 失败: %v", err)
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
							go s.startSftp(channel)
						} else {
							log.Printf("SFTP 子系统被禁用")
						}
					} else {
						log.Printf("未知的子系统: %s", subsystemName)
					}
				}

				if !ok && req.WantReply { // 只有当需要回复时才拒绝
					log.Printf("拒绝 %s 请求", req.Type)
					req.Reply(ok, nil) // 回复 false 表示拒绝
				} else if ok && req.WantReply {
					req.Reply(ok, nil) // 回复 true 表示接受
				}
			}
		}(requests)
	}
}

func (s *SSHServer) startSftp(channel ssh.Channel) {
	log.Print("启动 SFTP 子系统")
	serverOptions := []sftp.ServerOption{
		// sftp.WithDebug(os.Stderr), // 可以开启 SFTP 调试日志
	}

	if s.ReadOnlySftp {
		serverOptions = append(serverOptions, sftp.ReadOnly())
		log.Print("SFTP 服务器以只读模式运行")
	} else {
		log.Print("SFTP 服务器以读写模式运行")
	}

	server, err := sftp.NewServer(
		channel,
		serverOptions...,
	)
	if err != nil {
		log.Printf("启动 SFTP 服务器失败: %v", err)
		return // 启动失败直接返回
	}
	if err := server.Serve(); err == io.EOF {
		log.Print("SFTP 客户端退出会话。")
		server.Close()
	} else if err != nil {
		log.Printf("SFTP 服务器运行出错: %v", err)
		server.Close()
	}
	log.Print("SFTP 子系统已关闭")
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
