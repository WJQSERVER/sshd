package server

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sshd/config"
	"sshd/system"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// createPasswordCallback 返回一个封装了密码认证逻辑的闭包.
func createPasswordCallback(cfg *config.Config) func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if !cfg.AuthSettings.PasswordAuthentication {
			log.Printf("密码认证被禁用 (用户: %s)", conn.User())
			return nil, fmt.Errorf("password authentication is disabled")
		}

		username := conn.User()
		if username == "root" && (cfg.AuthSettings.PermitRootLogin == "no" || cfg.AuthSettings.PermitRootLogin == "prohibit-password") {
			log.Printf("Root 用户通过密码登录被拒绝 (PermitRootLogin: %s)", cfg.AuthSettings.PermitRootLogin)
			return nil, fmt.Errorf("root password login refused")
		}

		sysUser, err := system.LookupUser(username)
		if err != nil {
			log.Printf("密码认证失败: 系统用户 '%s' 未找到. %v", conn.User(), err)
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

		passwordMatch, err := system.VerifyPassword(string(password), shadowEntry.PasswordHash)
		if err != nil {
			log.Printf("密码认证错误: 用户 '%s' 密码校验时发生错误: %v", sysUser.Username, err)
			return nil, fmt.Errorf("authentication failed: password verification error")
		}

		if passwordMatch {
			log.Printf("用户 '%s' (系统用户 '%s') /etc/shadow 密码认证成功", conn.User(), sysUser.Username)
			return createPermissions(sysUser), nil
		}

		log.Printf("用户 '%s' (系统用户 '%s') /etc/shadow 密码认证失败 (密码不匹配)", conn.User(), sysUser.Username)
		return nil, fmt.Errorf("incorrect password")
	}
}

// createPublicKeyCallback 返回一个封装了公钥认证逻辑的闭包.
func createPublicKeyCallback(cfg *config.Config) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !cfg.AuthSettings.PubkeyAuthentication {
			log.Printf("公钥认证被禁用 (用户: %s)", conn.User())
			return nil, fmt.Errorf("public key authentication is disabled")
		}

		username := conn.User()
		if username == "root" && cfg.AuthSettings.PermitRootLogin == "no" {
			log.Printf("Root 用户通过公钥登录被拒绝 (PermitRootLogin: no)")
			return nil, fmt.Errorf("root public key login refused")
		}

		sysUser, err := system.LookupUser(username)
		if err != nil {
			log.Printf("公钥认证失败: 系统用户 '%s' 未找到. %v", username, err)
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
				log.Printf("用户 '%s' (系统用户 '%s') 公钥认证成功 (类型: %s)", conn.User(), sysUser.Username, key.Type())
				return createPermissions(sysUser), nil
			}
			authKeysBytes = rest
		}

		log.Printf("用户 '%s' (系统用户 '%s') 公钥认证失败", conn.User(), sysUser.Username)
		return nil, fmt.Errorf("public key authentication failed")
	}
}

// createPermissions 根据系统用户信息创建一个 ssh.Permissions 对象.
func createPermissions(sysUser *system.SystemUserInfo) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			"systemUserHome": sysUser.HomeDir,
			"systemUserUID":  sysUser.UID,
			"systemUserGID":  sysUser.GID,
			"systemUsername": sysUser.Username,
		},
	}
}
