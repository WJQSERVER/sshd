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
	UserHomesBaseDir  string `toml:"user_homes_base_dir"` // Base directory for user home directories
}

type AuthConfig struct {
	User               string `toml:"user"`
	Password           string `toml:"password"`
	AuthorizedKeysDir string `toml:"authorized_keys_dir"` // Directory for storing authorized_keys files
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
