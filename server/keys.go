package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sshd/config"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

const (
	defaultHostKeyFileRSA     = "host_rsa.key"
	defaultHostKeyFileEd25519 = "host_ed25519.key"
)

// loadOrCreateHostKey 加载或创建主机密钥并返回一个 ssh.Signer.
func loadOrCreateHostKey(cfg *config.Config) (ssh.Signer, error) {
	var privateKey interface{}
	var err error

	switch cfg.Server.Cert {
	case "ed25519":
		privateKey, err = loadOrCreateHostKeyEd25519(defaultHostKeyFileEd25519)
	case "rsa":
		privateKey, err = loadOrCreateHostKeyRSA(defaultHostKeyFileRSA)
	default:
		return nil, fmt.Errorf("配置文件中不支持的加密类型: %s", cfg.Server.Cert)
	}
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(privateKey)
}

// loadOrCreateHostKeyRSA 加载或创建 RSA 主机密钥.
func loadOrCreateHostKeyRSA(keyFile string) (*rsa.PrivateKey, error) {
	keyPath := filepath.Clean(keyFile) // 清理路径以防止路径遍历等安全问题

	// 尝试加载已存在的主机密钥
	keyBytes, err := os.ReadFile(keyPath)
	if err == nil {
		// 文件存在, 尝试解析
		block, _ := pem.Decode(keyBytes)
		if block != nil && block.Type == "RSA PRIVATE KEY" {
			privateKey, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if parseErr == nil {
				log.Println("加载已存在的 RSA 主机密钥")
				return privateKey, nil
			}
			log.Printf("解析已存在的 RSA 主机密钥失败: %v, 尝试重新生成", parseErr) // 解析失败则尝试重新生成
		} else {
			log.Println("RSA 主机密钥文件格式不正确, 尝试重新生成") // 文件格式不正确则尝试重新生成
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading RSA host key file failed: %v", err) // 其他读取错误
	}

	// 文件不存在或解析失败, 生成新的主机密钥
	log.Println("生成新的 RSA 主机密钥...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key failed: %v", err)
	}

	// 将私钥编码为 PEM 格式
	keyPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	pemBytes := pem.EncodeToMemory(keyPem)

	// 保存密钥到文件
	err = os.WriteFile(keyPath, pemBytes, 0600) // 设置权限为 0600 (仅所有者可读写)
	if err != nil {
		return nil, fmt.Errorf("saving RSA host key to file failed: %v", err)
	}
	log.Printf("RSA 主机密钥已保存到: %s", keyPath)

	return privateKey, nil
}

// loadOrCreateHostKeyEd25519 加载或创建 Ed25519 主机密钥.
func loadOrCreateHostKeyEd25519(keyFile string) (ed25519.PrivateKey, error) {
	keyPath := filepath.Clean(keyFile) // 清理路径以防止路径遍历等安全问题

	// 尝试加载已存在的主机密钥
	keyBytes, err := os.ReadFile(keyPath)
	if err == nil {
		// 文件存在, 尝试解析 PEM 编码的私钥
		block, _ := pem.Decode(keyBytes)                         // 首先进行 PEM 解码
		if block != nil && block.Type == "ED25519 PRIVATE KEY" { // 检查 PEM 类型
			privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes) // 使用 x509 解析 PKCS#8 格式的私钥
			if err == nil {
				if edKey, ok := privateKey.(ed25519.PrivateKey); ok { // 类型断言, 确保是 ed25519.PrivateKey
					log.Println("加载已存在的 Ed25519 主机密钥")
					return edKey, nil
				} else {
					log.Println("主机密钥文件内容不是 Ed25519 私钥, 尝试重新生成")
				}
			} else {
				log.Printf("解析已存在的 Ed25519 主机密钥失败: %v, 尝试重新生成", err) // 解析失败则尝试重新生成
			}
		} else {
			log.Println("Ed25519 主机密钥文件格式不正确, 尝试重新生成") // PEM 文件格式不正确则尝试重新生成
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading Ed25519 host key file failed: %v", err) // 其他读取错误
	}

	// 文件不存在或解析失败, 生成新的主机密钥
	log.Println("生成新的 Ed25519 主机密钥...")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 key failed: %v", err)
	}

	// 将私钥编码为 PEM 格式 (PKCS#8)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey) // 使用 x509 将 Ed25519 私钥编码为 PKCS#8 格式
	if err != nil {
		return nil, fmt.Errorf("encoding Ed25519 private key failed: %v", err)
	}
	keyPem := &pem.Block{
		Type:  "ED25519 PRIVATE KEY", // PEM 类型应设置为 "ED25519 PRIVATE KEY"
		Bytes: privateKeyBytes,
	}
	pemBytes := pem.EncodeToMemory(keyPem)

	// 保存密钥到文件
	err = os.WriteFile(keyPath, pemBytes, 0600) // 设置权限为 0600 (仅所有者可读写)
	if err != nil {
		return nil, fmt.Errorf("saving Ed25519 host key to file failed: %v", err)
	}
	log.Printf("Ed25519 主机密钥已保存到: %s", keyPath)

	return privateKey, nil
}

// handleGlobalRequests 处理 SSH 全局请求 (如 keep-alive).
func handleGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		// 对于大多数简单的服务器, 我们可以安全地忽略这些请求或拒绝它们.
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}
