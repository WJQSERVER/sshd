package middleware

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// LoginAttempt 记录一次登录尝试信息
type LoginAttempt struct {
	Timestamp time.Time
	Count     int
}

// Default configuration values for Fail2BanMiddleware
const (
	DefaultMaxAttempts = 5
	DefaultFindTime    = 10 * time.Minute
	DefaultBanTime     = 30 * time.Minute
)

// Fail2BanMiddlewareConfig 配置 Fail2Ban 中间件
type Fail2BanMiddlewareConfig struct {
	MaxAttempts         int           // 在被禁止前允许的最大失败尝试次数
	FindTime            time.Duration // 评估失败尝试的时间窗口
	BanTime             time.Duration // IP 被禁止的时长
	Whitelist           []string      // IP 地址白名单 (CIDR 格式, 例如 "192.168.1.0/24")
	whitelistNetworks   []*net.IPNet  // 解析后的白名单网络
}

// Fail2BanMiddleware 是一个实现 fail2ban 逻辑的中间件
type Fail2BanMiddleware struct {
	config         Fail2BanMiddlewareConfig
	failedAttempts map[string]*LoginAttempt // key: IP 地址, value: LoginAttempt
	bannedIPs      map[string]time.Time     // key: IP 地址, value: 解封时间
	mu             sync.RWMutex             // 保护 failedAttempts 和 bannedIPs 的并发访问
}

// NewFail2BanMiddleware 创建并初始化一个新的 Fail2BanMiddleware
func NewFail2BanMiddleware(config Fail2BanMiddlewareConfig) (*Fail2BanMiddleware, error) {
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = DefaultMaxAttempts
	}
	if config.FindTime <= 0 {
		config.FindTime = DefaultFindTime
	}
	if config.BanTime <= 0 {
		config.BanTime = DefaultBanTime
	}

	var parsedNetworks []*net.IPNet
	for _, cidr := range config.Whitelist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in whitelist '%s': %w", cidr, err)
		}
		parsedNetworks = append(parsedNetworks, ipNet)
	}
	config.whitelistNetworks = parsedNetworks

	fm := &Fail2BanMiddleware{
		config:         config,
		failedAttempts: make(map[string]*LoginAttempt),
		bannedIPs:      make(map[string]time.Time),
	}

	// 启动一个 goroutine 定期清理过期的 bannedIPs 和 failedAttempts
	// 以防止内存无限增长
	go fm.cleanupRoutine()

	return fm, nil
}

// isWhitelisted 检查给定的 IP 地址是否在白名单中
func (fm *Fail2BanMiddleware) isWhitelisted(ip net.IP) bool {
	for _, network := range fm.config.whitelistNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Handler 返回一个 MiddlewareFunc, 该函数应用 fail2ban 逻辑
func (fm *Fail2BanMiddleware) Handler() MiddlewareFunc {
	return func(next AuthHandlerFunc) AuthHandlerFunc {
		return func(ctx *AuthContext) (*Permissions, error) {
			// 从 AuthContext 中获取 IP 地址
			clientIP := getIPFromAuthContext(ctx.RemoteAddr)
			if clientIP == nil {
				// 如果无法获取 IP 地址, 则无法应用 fail2ban 逻辑, 直接跳过
				// log.Printf("Fail2Ban: Could not determine IP from RemoteAddr: %T %v", ctx.RemoteAddr, ctx.RemoteAddr)
				return next(ctx)
			}

			ipStr := clientIP.String()

			// 0. 检查白名单
			if fm.isWhitelisted(clientIP) {
				// log.Printf("Fail2Ban: IP %s is whitelisted, skipping checks.", ipStr)
				return next(ctx)
			}

			fm.mu.RLock()
			// 1. 检查 IP 是否已被禁止
			unbanTime, isBanned := fm.bannedIPs[ipStr]
			fm.mu.RUnlock()

			if isBanned {
				if time.Now().Before(unbanTime) {
					// log.Printf("Fail2Ban: IP %s is currently banned until %v. Connection rejected.", ipStr, unbanTime)
					ctx.AbortWithError(fmt.Errorf("IP address %s is temporarily banned due to too many failed login attempts", ipStr))
					return nil, ctx.Error()
				}
				// 如果解封时间已过, 则解除禁止
				fm.mu.Lock()
				delete(fm.bannedIPs, ipStr)
				// log.Printf("Fail2Ban: Ban for IP %s has expired. Unbanning.", ipStr)
				fm.mu.Unlock()
			}

			// 调用链中的下一个处理器
			// log.Printf("Fail2Ban: IP %s not banned, proceeding with authentication for user %s.", ipStr, ctx.User)
			permissions, err := next(ctx)

			authFailed := (err != nil && permissions == nil) || (ctx.IsAborted() && ctx.Error() != nil)

			if authFailed {
				// log.Printf("Fail2Ban: Authentication failed for user %s from IP %s. Error: %v. Aborted: %v, AbortError: %v", ctx.User, ipStr, err, ctx.IsAborted(), ctx.Error())
				fm.mu.Lock()
				defer fm.mu.Unlock()

				var currentAttempt *LoginAttempt // Will hold the up-to-date attempt record

				attemptOnEntry, exists := fm.failedAttempts[ipStr]
				now := time.Now()

				if !exists || now.Sub(attemptOnEntry.Timestamp) > fm.config.FindTime {
					// Path A: New attempt or find time expired
					// log.Printf("Fail2Ban: New failed attempt or find time window expired for IP %s. Count set to 1.", ipStr)
					currentAttempt = &LoginAttempt{Timestamp: now, Count: 1}
					fm.failedAttempts[ipStr] = currentAttempt
				} else {
					// Path B: Existing attempt within find time
					attemptOnEntry.Count++
					attemptOnEntry.Timestamp = now
					currentAttempt = attemptOnEntry
					// log.Printf("Fail2Ban: Incremented failed attempt count for IP %s to %d.", ipStr, currentAttempt.Count)
				}

				// Unified ban logic using currentAttempt, executed regardless of which path (A or B) was taken
				if currentAttempt.Count >= fm.config.MaxAttempts {
					banUntil := now.Add(fm.config.BanTime)
					fm.bannedIPs[ipStr] = banUntil
					// log.Printf("Fail2Ban: IP %s banned until %v due to %d failed attempts.", ipStr, banUntil, currentAttempt.Count)
					delete(fm.failedAttempts, ipStr) // Remove from attempts map as it's now banned
				}
			} else if permissions != nil && err == nil { // Authentication successful
				// log.Printf("Fail2Ban: Authentication successful for user %s from IP %s. Clearing failed attempts for this IP.", ctx.User, ipStr)
				fm.mu.Lock()
				delete(fm.failedAttempts, ipStr)
				fm.mu.Unlock()
			}

			return permissions, err
		}
	}
}

// cleanupRoutine 定期清理过期的禁止IP和失败尝试记录
func (fm *Fail2BanMiddleware) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		fm.mu.Lock()
		for ip, unbanTime := range fm.bannedIPs {
			if now.After(unbanTime) {
				delete(fm.bannedIPs, ip)
				// log.Printf("Fail2Ban Cleanup: Removed expired ban for IP %s.", ip)
			}
		}
		for ip, attempt := range fm.failedAttempts {
			if now.Sub(attempt.Timestamp) > fm.config.FindTime {
				delete(fm.failedAttempts, ip)
				// log.Printf("Fail2Ban Cleanup: Removed stale failed attempt record for IP %s.", ip)
			}
		}
		fm.mu.Unlock()
	}
}

// getIPFromAuthContext 从 net.Addr 中提取 net.IP
func getIPFromAuthContext(addr net.Addr) net.IP {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	if ipAddr, ok := addr.(*net.IPAddr); ok { // 通常 ssh.ConnMetadata.RemoteAddr() 是 *net.TCPAddr
		return ipAddr.IP
	}
	// 在 SSH 的上下文中, RemoteAddr 通常是 *net.TCPAddr.
	// 如果是其他类型且包含 IP, 需要在这里添加处理.
	// 例如, 如果 ssh 包内部使用了 pipe 用于测试, RemoteAddr 可能是 mock 类型.
	return nil
}
