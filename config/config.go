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

type Config struct {
	Server ServerConfig `toml:"server"`
	Auth   AuthConfig   `toml:"auth"`
}

type ServerConfig struct {
	Host               string `toml:"host"`
	Port               int    `toml:"port"`
	Cert               string `toml:"cert"`
	SftpEnabled        bool   `toml:"sftp_enabled"`
	SftpReadonly       bool   `toml:"sftp_readonly"`
	// UserHomesBaseDir  string `toml:"user_homes_base_dir"` // Removed: System user homes are now used
}

// AuthSettingsConfig holds sshd-like authentication settings
type AuthSettingsConfig struct {
	PasswordAuthentication bool   `toml:"password_authentication"`
	PubkeyAuthentication   bool   `toml:"pubkey_authentication"`
	PermitRootLogin        string `toml:"permit_root_login"` // e.g., "yes", "no", "prohibit-password"
}

type AuthConfig struct {
	User     string `toml:"user"`     // Kept for now, but its role is diminished (only for initial non-system fallback if any)
	Password string `toml:"password"` // Kept for now, but its role is diminished
	// AuthorizedKeysDir string `toml:"authorized_keys_dir"` // Removed
}

type Config struct {
	Server       ServerConfig       `toml:"server"`
	Auth         AuthConfig         `toml:"auth"`
	AuthSettings AuthSettingsConfig `toml:"auth_settings"` // New section for auth behavior
}

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
