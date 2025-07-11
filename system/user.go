package system

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/go-crypt/crypt"
	// "github.com/go-crypt/crypt/algorithm" // 使用 CheckPassword 后不再需要特定的错误常量
)

// SystemUserInfo 保存系统用户的基本信息.
type SystemUserInfo struct {
	Username string // 用户名
	UID      string // 用户ID
	GID      string // 组ID
	HomeDir  string // 主目录
	Shell    string // 默认shell, 可能并非所有认证类型都需要或可用
}

// ShadowEntry 保存从 /etc/shadow 行解析的字段.
// 字段名对应标准的 shadow 文件字段.
type ShadowEntry struct {
	Username       string // 用户名
	PasswordHash   string // 加密的密码哈希
	LastChange     int64  // 自1970年1月1日以来的天数, 表示上次密码更改时间
	MinAge         int64  // 两次密码更改之间的最小天数
	MaxAge         int64  // 密码更改前所需的最大天数
	WarnPeriod     int64  // 密码过期前警告用户的天数
	InactivePeriod int64  // 密码过期后账户禁用的天数
	ExpiryDate     int64  // 自1970年1月1日以来的天数, 表示账户禁用的日期
	Reserved       string // 保留字段
}

// LookupUser 查询操作系统以获取给定用户名的详细信息.
func LookupUser(username string) (*SystemUserInfo, error) {
	sysUser, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("system user '%s' not found: %w", username, err)
	}

	// Shell 信息并非在所有操作系统的 user.User 中都直接可用 (例如 Windows).
	// 对于 Linux/macOS, 它通常位于 /etc/passwd 中, user.Lookup 会读取该文件.
	// 但是, user.User 并没有直接暴露 shell 字段.
	// 如果可能, 我们将检索它, 但对于所有 SSH 操作而言, 它并非至关重要.
	// 目前, 我们将其留空, 如果需要, 以后可以使用特定于平台的方法进行增强
	// 或者在绝对必要时解析 /etc/passwd (尽管首选 os/user).
	// 注意: Gid 是主组 ID. Uid 是用户 ID.

	return &SystemUserInfo{
		Username: sysUser.Username,
		UID:      sysUser.Uid,
		GID:      sysUser.Gid,
		HomeDir:  sysUser.HomeDir,
		Shell:    "", // 暂时留空, user.User 不直接提供 shell.
	}, nil
}

// GetUserShell 尝试获取用户的默认 shell.
// 如果需要更健壮的, 特定于平台的实现, 则这是一个占位符.
// 在 POSIX 系统上, user.Lookup *确实*会解析 /etc/passwd, 但 shell 字段未在结构体中暴露.
// 对于许多 SSH 操作 (例如 SFTP 或通过 "exec" 直接执行命令), 并不严格需要 shell.
// 对于交互式 "shell" 请求, 我们可能需要改进此功能或回退到默认值, 如 "sh" 或 "bash".
func (sui *SystemUserInfo) GetUserShell() string {
	if sui.Shell != "" {
		return sui.Shell
	}
	// 如果未指定或找到 shell, 则为常见默认值.
	// 如果用户的 shell 无效或为 /sbin/nologin, 系统 `sshd` 通常默认为 /bin/sh.
	// 对于 root, 它通常是 /bin/bash 或 /bin/sh.
	// 当我们实现用户模拟和实际的 shell 生成时, 此部分将需要更多考虑.
	// 目前, 如果未找到其他内容, 我们可以假定 'sh' 是一个非常基本的默认值.
	// `os/user` 包不提供 shell.
	// 我们可能需要在以后使 `server.defaultShell` 更智能或可配置.
	return "/bin/sh" // 一个常见的安全默认值
}

const shadowFilePath = "/etc/shadow"

// GetShadowEntryForUser 读取 /etc/shadow 并返回指定用户名的 ShadowEntry.
// 此函数必须以 root 权限运行才能读取 /etc/shadow.
func GetShadowEntryForUser(username string) (*ShadowEntry, error) {
	if os.Geteuid() != 0 { // 检查有效用户ID是否为root
		return nil, fmt.Errorf("reading %s requires root privileges", shadowFilePath)
	}

	file, err := os.Open(shadowFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", shadowFilePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parseShadowLine(line)
		if err != nil {
			// 记录格式错误的行但继续扫描, 避免因单行错误导致整个功能失败
			// log.Printf("Warning: skipping malformed shadow entry: %v (line: %s)", err, line)
			continue
		}
		if entry.Username == username {
			return entry, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %w", shadowFilePath, err)
	}

	return nil, fmt.Errorf("user '%s' not found in %s", username, shadowFilePath)
}

// parseShadowLine 解析 /etc/shadow 文件中的单行.
func parseShadowLine(line string) (*ShadowEntry, error) {
	fields := strings.Split(line, ":")
	if len(fields) < 8 { // 至少需要8个字段, 保留字段可以为空(8个字段), 或存在(9个字段)
		return nil, fmt.Errorf("invalid shadow line: expected at least 8 fields, got %d", len(fields))
	}

	entry := &ShadowEntry{
		Username:     fields[0],
		PasswordHash: fields[1],
	}

	var err error
	// 逐个解析字段, 并处理空字段的情况
	if fields[2] != "" {
		entry.LastChange, err = strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid LastChange field '%s': %w", fields[2], err)
		}
	}
	if fields[3] != "" {
		entry.MinAge, err = strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid MinAge field '%s': %w", fields[3], err)
		}
	}
	if fields[4] != "" {
		entry.MaxAge, err = strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid MaxAge field '%s': %w", fields[4], err)
		}
	}
	if fields[5] != "" {
		entry.WarnPeriod, err = strconv.ParseInt(fields[5], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid WarnPeriod field '%s': %w", fields[5], err)
		}
	}
	if fields[6] != "" {
		entry.InactivePeriod, err = strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid InactivePeriod field '%s': %w", fields[6], err)
		}
	}
	if fields[7] != "" {
		entry.ExpiryDate, err = strconv.ParseInt(fields[7], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid ExpiryDate field '%s': %w", fields[7], err)
		}
	}
	if len(fields) > 8 { // 如果存在第9个字段 (保留字段)
		entry.Reserved = fields[8]
	}

	return entry, nil
}

// VerifyPassword 检查给定的明文密码是否与 /etc/shadow 中的哈希密码匹配
// (哈希密码包括算法, salt 和哈希值).
// 它使用 github.com/go-crypt/crypt 来验证各种 crypt(3) 风格的哈希.
func VerifyPassword(plainPassword, shadowHash string) (bool, error) {
	// crypt.CheckPassword 返回 (valid bool, err error).
	// 如果 err 不为 nil, 则表示在检查过程中发生错误 (例如, 无效的哈希格式).
	// 如果 err 为 nil, 则 valid 表示密码是否与哈希匹配.
	valid, err := crypt.CheckPassword(plainPassword, shadowHash)
	if err != nil {
		// crypt.CheckPassword 过程本身发生错误 (例如, 格式错误的哈希字符串,
		// 不支持的算法未被简单的缀检查捕获等).
		// 此处并不意味着密码不匹配. 对于不匹配的情况, err 为 nil 且 valid 为 false.
		return false, fmt.Errorf("password check process failed for hash '%s': %w", shadowHash, err)
	}

	// 如果 err 为 nil, 'valid' 保存密码比较的结果.
	if !valid {
		// 这是密码不匹配的情况. 返回 false (不匹配) 和 nil 错误 (过程正常).
		return false, nil
	}

	// 密码匹配
	return true, nil
}
