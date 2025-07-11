package config

import (
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
	}
}
