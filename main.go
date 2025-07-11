package main

import (
	"log"
	"sshd/config"
	"sshd/server"
)

const (
	defaultHostKeyFileRSA     = "host_rsa.key"
	defaultHostKeyFileEd25519 = "host_ed25519.key"
	configFilePath            = "config/config.toml"
)

// EncryptionType 定义支持的加密类型.
type EncryptionType string

const (
	RSAEncryption     EncryptionType = "rsa"     // RSA 加密类型
	Ed25519Encryption EncryptionType = "ed25519" // Ed25519 加密类型
)

var (
	cfg *config.Config
)

func loadConfig() {
	var err error
	cfg, err = config.LoadConfig(configFilePath)
	if err != nil {
		// 如果配置加载失败, 这是致命错误, 程序无法继续.
		log.Fatalf("无法加载配置文件 '%s': %v", configFilePath, err)
	}
}

func init() {
	loadConfig()
}

func main() {
	// 将加载好的配置对象 cfg 传递给 server.NewServer 构造函数.
	// 所有复杂的初始化逻辑, 如加载/生成主机密钥、创建认证回调等,
	// 都已完全封装在 server 包的 NewServer 函数内部.
	appServer, err := server.NewServer(cfg)
	if err != nil {
		// 如果服务器实例创建失败 (例如, 主机密钥无法创建), 也是致命错误.
		log.Fatalf("创建 SSH 服务器失败: %v", err)
	}

	// 打印一条启动信息, 告知用户服务器正在哪个地址和端口上监听.
	log.Printf("SSH 服务器启动中, 监听地址 %s:%d...", cfg.Server.Host, cfg.Server.Port)

	// 调用 Start() 方法. 这个方法会阻塞主 goroutine, 开始监听和接受连接.
	// 如果 Start() 方法返回错误 (例如, 端口被占用), 这同样是致命的.
	if err := appServer.Start(); err != nil {
		log.Fatalf("SSH 服务器启动失败: %v", err)
	}

}
