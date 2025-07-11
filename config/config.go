package config

/*
[server]
host = ""
port = 22
cert = "ed25519" # ed25519/rsa

[auth]
user = ""
password = ""

*/

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// ServerConfig 定义服务器相关的配置
type ServerConfig struct {
	Host         string `toml:"host"`          // 服务器监听的主机地址
	Port         int    `toml:"port"`          // 服务器监听的端口
	Cert         string `toml:"cert"`          // 使用的证书类型, 例如 "ed25519" 或 "rsa"
	SftpEnabled  bool   `toml:"sftp_enabled"`  // 是否启用 SFTP 功能
	SftpReadonly bool   `toml:"sftp_readonly"` // SFTP 是否为只读模式
}

// AuthSettingsConfig 保存类似 sshd 的认证设置
type AuthSettingsConfig struct {
	PasswordAuthentication bool   `toml:"password_authentication"` // 是否启用密码认证
	PubkeyAuthentication   bool   `toml:"pubkey_authentication"`   // 是否启用公钥认证
	PermitRootLogin        string `toml:"permit_root_login"`       // 是否允许 root 用户登录, 例如 "yes", "no", "prohibit-password"
}

// AuthConfig 定义认证相关的配置 (主要用于旧版或特定回退逻辑)
type AuthConfig struct {
	User     string `toml:"user"`     // 用户名 (其作用已减弱, 可能仅用于初始非系统用户回退)
	Password string `toml:"password"` // 密码 (其作用已减弱)
}

// Config 是所有配置项的根结构体
type Config struct {
	Server       ServerConfig       `toml:"server"`        // 服务器配置节
	Auth         AuthConfig         `toml:"auth"`          // 认证配置节 (旧)
	AuthSettings AuthSettingsConfig `toml:"auth_settings"` // 认证行为配置节
}

// LoadConfig 从指定路径加载配置文件
func LoadConfig(path string) (*Config, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("config file not found: %v", err)
	}
	var config Config
	_, err = toml.DecodeFile(path, &config)
	if err != nil {
		return nil, fmt.Errorf("config file decode error: %v", err)
	}
	return &config, nil
}
