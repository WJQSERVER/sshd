package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sshd/server"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

const (
	defaultHostKeyFileRSA     = "host_rsa.key"     // RSA 主机密钥文件路径
	defaultHostKeyFileEd25519 = "host_ed25519.key" // Ed25519 主机密钥文件路径
)

// EncryptionType 定义支持的加密类型
type EncryptionType string

const (
	RSAEncryption     EncryptionType = "rsa"
	Ed25519Encryption EncryptionType = "ed25519"
)

func main() {
	// 设置优先使用的加密类型
	encryptionType := Ed25519Encryption // 优先使用 Ed25519，可以修改为 RSAEncryption

	var privateKey interface{}
	var err error
	var hostKeyFile string

	switch encryptionType {
	case Ed25519Encryption:
		hostKeyFile = defaultHostKeyFileEd25519
		privateKey, err = loadOrCreateHostKeyEd25519(hostKeyFile)
	case RSAEncryption:
		hostKeyFile = defaultHostKeyFileRSA
		privateKey, err = loadOrCreateHostKeyRSA(hostKeyFile)
	default:
		log.Fatalf("不支持的加密类型: %s", encryptionType)
	}

	if err != nil {
		log.Fatalf("加载或创建主机密钥失败: %v", err)
	}

	// 创建 signer (用于 ssh.ServerConfig)
	var signer ssh.Signer
	switch pk := privateKey.(type) {
	case *rsa.PrivateKey:
		signer, err = ssh.NewSignerFromKey(pk)
	case ed25519.PrivateKey:
		signer, err = ssh.NewSignerFromKey(pk)
	default:
		log.Fatalf("不支持的私钥类型")
	}
	if err != nil {
		log.Fatalf("创建 signer 失败: %v", err)
	}

	// 2. 配置 ssh.ServerConfig
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			// 简单的密码认证示例 (请勿在生产环境中使用硬编码密码!)
			if conn.User() == "root" && string(password) == "test" {
				log.Printf("用户 '%s' 密码认证成功", conn.User())
				return nil, nil // 认证成功
			}
			log.Printf("用户 '%s' 密码认证失败", conn.User())
			return nil, fmt.Errorf("密码错误") // 认证失败
		},
		// 可以添加 PublicKeyCallback 来支持公钥认证
	}
	config.AddHostKey(signer) // 添加主机密钥

	// 3. 创建 SSHServer 实例
	server := &server.SSHServer{
		Port: 2200, // 监听端口，可以修改
		//Address:      "0.0.0.0", // 监听地址，0.0.0.0 表示监听所有网卡
		Server:       config,
		EnableSftp:   true,  // 启用 SFTP
		ReadOnlySftp: false, // SFTP 读写权限

	}

	// 将主机密钥存储到 Server 实例中
	switch encryptionType {
	case RSAEncryption:
		if pk, ok := privateKey.(*rsa.PrivateKey); ok {
			server.HostKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
		}
	case Ed25519Encryption:
		if pk, ok := privateKey.(ed25519.PrivateKey); ok {
			privateKeySSH, err := ssh.NewSignerFromKey(pk)
			if err != nil {
				log.Fatalf("创建 SSH 私钥失败: %v", err)
			}
			server.HostKey = ssh.MarshalAuthorizedKey(privateKeySSH.PublicKey())
		}
	}

	// 4. 启动服务器
	log.Println("SSH 服务器启动...")
	server.Start()
}

// loadOrCreateHostKeyRSA 加载或创建 RSA 主机密钥
func loadOrCreateHostKeyRSA(keyFile string) (*rsa.PrivateKey, error) {
	keyPath := filepath.Clean(keyFile) // 清理路径，防止安全问题

	// 尝试加载已存在的主机密钥
	keyBytes, err := os.ReadFile(keyPath)
	if err == nil {
		// 文件存在，尝试解析
		block, _ := pem.Decode(keyBytes)
		if block != nil && block.Type == "RSA PRIVATE KEY" {
			privateKey, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if parseErr == nil {
				log.Println("加载已存在的 RSA 主机密钥")
				return privateKey, nil
			}
			log.Printf("解析已存在的 RSA 主机密钥失败: %v, 尝试重新生成", parseErr) // 解析失败，尝试重新生成
		} else {
			log.Println("RSA 主机密钥文件格式不正确，尝试重新生成") // 文件格式不正确，尝试重新生成
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取 RSA 主机密钥文件失败: %v", err) // 其他读取错误
	}

	// 文件不存在或解析失败，生成新的主机密钥
	log.Println("生成新的 RSA 主机密钥...")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成 RSA 密钥失败: %v", err)
	}

	// 将私钥编码为 PEM 格式
	keyPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	pemBytes := pem.EncodeToMemory(keyPem)

	// 保存密钥到文件
	err = os.WriteFile(keyPath, pemBytes, 0600) // 权限设置为 0600 (只有所有者可读写)
	if err != nil {
		return nil, fmt.Errorf("保存 RSA 主机密钥到文件失败: %v", err)
	}
	log.Printf("RSA 主机密钥已保存到: %s", keyPath)

	return privateKey, nil
}

// loadOrCreateHostKeyEd25519 加载或创建 Ed25519 主机密钥
func loadOrCreateHostKeyEd25519(keyFile string) (ed25519.PrivateKey, error) {
	keyPath := filepath.Clean(keyFile) // 清理路径，防止安全问题

	// 尝试加载已存在的主机密钥
	keyBytes, err := os.ReadFile(keyPath)
	if err == nil {
		// 文件存在，尝试解析 PEM 编码的私钥
		block, _ := pem.Decode(keyBytes)                         // 先 PEM 解码
		if block != nil && block.Type == "ED25519 PRIVATE KEY" { // 检查 PEM 类型
			privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes) // 使用 x509 解析 PKCS#8 格式的私钥
			if err == nil {
				if edKey, ok := privateKey.(ed25519.PrivateKey); ok { // 类型断言
					log.Println("加载已存在的 Ed25519 主机密钥")
					return edKey, nil
				} else {
					log.Println("主机密钥文件内容不是 Ed25519 私钥，尝试重新生成")
				}
			} else {
				log.Printf("解析已存在的 Ed25519 主机密钥失败: %v, 尝试重新生成", err) // 解析失败，尝试重新生成
			}
		} else {
			log.Println("Ed25519 主机密钥文件格式不正确，尝试重新生成") // PEM 文件格式不正确，尝试重新生成
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取 Ed25519 主机密钥文件失败: %v", err) // 其他读取错误
	}

	// 文件不存在或解析失败，生成新的主机密钥
	log.Println("生成新的 Ed25519 主机密钥...")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 Ed25519 密钥失败: %v", err)
	}

	// 将私钥编码为 PEM 格式 (PKCS#8)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey) // 使用 x509 将 Ed25519 私钥编码为 PKCS#8 格式
	if err != nil {
		return nil, fmt.Errorf("编码 Ed25519 私钥失败: %v", err)
	}
	keyPem := &pem.Block{
		Type:  "ED25519 PRIVATE KEY", // PEM 类型需要设置为 "ED25519 PRIVATE KEY"
		Bytes: privateKeyBytes,
	}
	pemBytes := pem.EncodeToMemory(keyPem)

	// 保存密钥到文件
	err = os.WriteFile(keyPath, pemBytes, 0600) // 权限设置为 0600 (只有所有者可读写)
	if err != nil {
		return nil, fmt.Errorf("保存 Ed25519 主机密钥到文件失败: %v", err)
	}
	log.Printf("Ed25519 主机密钥已保存到: %s", keyPath)

	return privateKey, nil
}
