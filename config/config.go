package config

import (
	"os"
	"time"

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

// Fail2BanConfig 定义 Fail2Ban 中间件的配置
type Fail2BanConfig struct {
	Enabled     bool          `toml:"enabled"`      // 是否启用 Fail2Ban
	MaxAttempts int           `toml:"max_attempts"` // 最大尝试次数
	FindTime    time.Duration `toml:"find_time"`    // 查找时间窗口 (例如 "10m", "1h")
	BanTime     time.Duration `toml:"ban_time"`     // 封禁时长 (例如 "30m", "24h")
	Whitelist   []string      `toml:"whitelist"`    // IP白名单 (CIDR格式, 例如 "192.168.1.0/24")
}

// Config 是所有配置项的根结构体
type Config struct {
	Server       ServerConfig       `toml:"server"`        // 服务器配置节
	Auth         AuthConfig         `toml:"auth"`          // 认证配置节 (旧)
	AuthSettings AuthSettingsConfig `toml:"auth_settings"` // 认证行为配置节
	Fail2Ban     Fail2BanConfig     `toml:"fail2ban"`      // Fail2Ban 配置节
}

// LoadConfig 从 TOML 配置文件加载配置
func LoadConfig(filePath string) (*Config, error) {
	if !FileExists(filePath) {
		// 楔入配置文件
		err := DefaultConfig().WriteConfig(filePath)
		if err != nil {
			return nil, err
		}
		return DefaultConfig(), nil
	}

	var config Config
	if _, err := toml.DecodeFile(filePath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// 写入配置文件
func (c *Config) WriteConfig(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := toml.NewEncoder(file)
	return encoder.Encode(c)
}

// 检测文件是否存在
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// 默认配置
/*
[server]
host = "0.0.0.0" # Listen on all interfaces
port = 2200
cert = "ed25519" # ed25519 or rsa
sftp_enabled = true
sftp_readonly = false

[auth] # This section is mostly for legacy/fallback if system auth fails or for a non-system bootstrap user.
user = "testuser" # This user/password is now only for temporary fallback during transition to PAM
password = "testpass" # Please change this in a production environment!

[auth_settings]
password_authentication = true # Enable/disable password authentication via /etc/shadow
pubkey_authentication = true   # Enable/disable public key authentication
permit_root_login = "prohibit-password" # Options: "yes", "no", "prohibit-password"

*/
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:        "0.0.0.0",
			Port:        2200,
			Cert:        "ed25519",
			SftpEnabled: true,
		},
		Auth: AuthConfig{
			User:     "testuser",
			Password: "testpass",
		},
		AuthSettings: AuthSettingsConfig{
			PasswordAuthentication: true,
			PubkeyAuthentication:   true,
			PermitRootLogin:        "prohibit-password",
		},
		Fail2Ban: Fail2BanConfig{
			Enabled:     true, // 默认启用
			MaxAttempts: 5,
			FindTime:    10 * time.Minute,
			BanTime:     30 * time.Minute,
			Whitelist:   []string{"127.0.0.1/32", "::1/128"}, // 默认只白名单本机
		},
	}
}
