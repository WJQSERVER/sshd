package server

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sshd/internal/middleware" // 新增导入
	"sshd/config"
	"sshd/system"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// CorePasswordAuthenticator 执行核心的密码认证逻辑.
// 它符合 middleware.AuthHandlerFunc 的期望 (尽管它额外需要 cfg).
func CorePasswordAuthenticator(cfg *config.Config, authCtx *middleware.AuthContext) (*middleware.Permissions, error) {
	if !cfg.AuthSettings.PasswordAuthentication {
		log.Printf("密码认证被禁用 (用户: %s)", authCtx.User)
		return nil, fmt.Errorf("password authentication is disabled")
	}

	if authCtx.User == "root" && (cfg.AuthSettings.PermitRootLogin == "no" || cfg.AuthSettings.PermitRootLogin == "prohibit-password") {
		log.Printf("Root 用户通过密码登录被拒绝 (PermitRootLogin: %s)", cfg.AuthSettings.PermitRootLogin)
		return nil, fmt.Errorf("root password login refused")
	}

	passwordBytes, ok := authCtx.Get("password")
	if !ok {
		return nil, fmt.Errorf("password not found in auth context for user %s", authCtx.User)
	}
	passwordStr, ok := passwordBytes.(string)
	if !ok {
		return nil, fmt.Errorf("password in context is not a string for user %s", authCtx.User)
	}

	sysUser, err := system.LookupUser(authCtx.User)
	if err != nil {
		log.Printf("密码认证失败: 系统用户 '%s' 未找到. %v", authCtx.User, err)
		return nil, fmt.Errorf("password authentication failed: user not found or system error")
	}

	shadowEntry, err := system.GetShadowEntryForUser(sysUser.Username)
	if err != nil {
		log.Printf("密码认证失败: 无法获取用户 '%s' 的 shadow 条目: %v", sysUser.Username, err)
		return nil, fmt.Errorf("authentication failed: internal server error")
	}

	if shadowEntry.PasswordHash == "" || strings.HasPrefix(shadowEntry.PasswordHash, "!") || strings.HasPrefix(shadowEntry.PasswordHash, "*") {
		log.Printf("密码认证失败: 用户 '%s' 账户已锁定或无密码登录权限", sysUser.Username)
		return nil, fmt.Errorf("password authentication failed: account locked or no password login")
	}

	todayInDays := time.Now().Unix() / (60 * 60 * 24)
	if shadowEntry.ExpiryDate > 0 && todayInDays > shadowEntry.ExpiryDate {
		log.Printf("密码认证失败: 用户 '%s' 账户已过期", sysUser.Username)
		return nil, fmt.Errorf("password authentication failed: account expired")
	}

	if shadowEntry.MaxAge > 0 && shadowEntry.MaxAge < 99999 {
		passwordExpiryDay := shadowEntry.LastChange + shadowEntry.MaxAge
		if todayInDays > passwordExpiryDay {
			log.Printf("密码认证失败: 用户 '%s' 的密码已过期", sysUser.Username)
			return nil, fmt.Errorf("password authentication failed: password expired")
		}
	}

	passwordMatch, err := system.VerifyPassword(passwordStr, shadowEntry.PasswordHash)
	if err != nil {
		log.Printf("密码认证错误: 用户 '%s' 密码校验时发生错误: %v", sysUser.Username, err)
		return nil, fmt.Errorf("authentication failed: password verification error")
	}

	if passwordMatch {
		log.Printf("用户 '%s' (系统用户 '%s') /etc/shadow 密码认证成功", authCtx.User, sysUser.Username)
		return createPermissions(sysUser), nil
	}

	log.Printf("用户 '%s' (系统用户 '%s') /etc/shadow 密码认证失败 (密码不匹配)", authCtx.User, sysUser.Username)
	return nil, fmt.Errorf("incorrect password")
}

// CorePublicKeyAuthenticator 执行核心的公钥认证逻辑.
func CorePublicKeyAuthenticator(cfg *config.Config, authCtx *middleware.AuthContext) (*middleware.Permissions, error) {
	if !cfg.AuthSettings.PubkeyAuthentication {
		log.Printf("公钥认证被禁用 (用户: %s)", authCtx.User)
		return nil, fmt.Errorf("public key authentication is disabled")
	}

	if authCtx.User == "root" && cfg.AuthSettings.PermitRootLogin == "no" {
		log.Printf("Root 用户通过公钥登录被拒绝 (PermitRootLogin: no)")
		return nil, fmt.Errorf("root public key login refused")
	}

	sshKey, ok := authCtx.Get("publickey")
	if !ok {
		return nil, fmt.Errorf("public key not found in auth context for user %s", authCtx.User)
	}
	key, ok := sshKey.(ssh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key in context is not a ssh.PublicKey for user %s", authCtx.User)
	}

	sysUser, err := system.LookupUser(authCtx.User)
	if err != nil {
		log.Printf("公钥认证失败: 系统用户 '%s' 未找到. %v", authCtx.User, err)
		return nil, fmt.Errorf("public key authentication failed: user not found")
	}

	authKeysFile := filepath.Join(sysUser.HomeDir, ".ssh", "authorized_keys")
	authKeysBytes, err := os.ReadFile(authKeysFile)
	if err != nil {
		log.Printf("公钥认证失败: 读取 authorized_keys 文件 '%s' 失败: %v", authKeysFile, err)
		return nil, fmt.Errorf("cannot read authorized_keys file")
	}

	for len(authKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authKeysBytes)
		if err != nil {
			log.Printf("解析 authorized_keys 文件 '%s' 失败: %v", authKeysFile, err)
			return nil, fmt.Errorf("cannot parse key in authorized_keys file")
		}
		if bytes.Equal(key.Marshal(), pubKey.Marshal()) {
			log.Printf("用户 '%s' (系统用户 '%s') 公钥认证成功 (类型: %s)", authCtx.User, sysUser.Username, key.Type())
			return createPermissions(sysUser), nil
		}
		authKeysBytes = rest
	}

	log.Printf("用户 '%s' (系统用户 '%s') 公钥认证失败", authCtx.User, sysUser.Username)
	return nil, fmt.Errorf("public key authentication failed")
}

// createPermissions 根据系统用户信息创建一个 ssh.Permissions 对象.
// middleware.Permissions 将包含更丰富的权限信息.
// 对于这个初始集成, 我们主要关注认证成功/失败.
// 具体的权限字段可以根据需要填充.
func createPermissions(sysUser *system.SystemUserInfo) *middleware.Permissions {
	// 示例: 可以根据 sysUser 信息设置更细致的权限
	return &middleware.Permissions{
		CanExecuteCommands: true, // 默认允许执行命令
		// AllowedCommands: []string{}, // 可以限制命令
		// Environment: []string{fmt.Sprintf("SYSTEM_USER_HOME=%s", sysUser.HomeDir)},
		// 可以将 ssh.Permissions 的 Extensions 映射到 middleware.Permissions 的自定义字段或一个通用 map
		// CustomData: map[string]string{
		// 	"systemUserHome": sysUser.HomeDir,
		// 	"systemUserUID":  sysUser.UID,
		// 	"systemUserGID":  sysUser.GID,
		// 	"systemUsername": sysUser.Username,
		// },
	}
}
