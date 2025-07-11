package main

import (
	"bytes" // Import bytes package for key comparison
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sshd/config" // Import the config package
	"sshd/server"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

const (
	defaultHostKeyFileRSA     = "host_rsa.key"
	defaultHostKeyFileEd25519 = "host_ed25519.key"
	configFilePath            = "config/config.toml"
)

// EncryptionType 定义支持的加密类型
type EncryptionType string

const (
	RSAEncryption     EncryptionType = "rsa"
	Ed25519Encryption EncryptionType = "ed25519"
)

func main() {
	// 1. Load configuration
	cfg, err := config.LoadConfig(configFilePath)
	if err != nil {
		log.Fatalf("无法加载配置文件 '%s': %v", configFilePath, err)
	}

	// 2. Determine encryption type and load/create host key
	var privateKey interface{}
	var hostKeyFile string
	encryptionType := EncryptionType(cfg.Server.Cert)

	switch encryptionType {
	case Ed25519Encryption:
		hostKeyFile = defaultHostKeyFileEd25519
		privateKey, err = loadOrCreateHostKeyEd25519(hostKeyFile)
	case RSAEncryption:
		hostKeyFile = defaultHostKeyFileRSA
		privateKey, err = loadOrCreateHostKeyRSA(hostKeyFile)
	default:
		log.Fatalf("配置文件中不支持的加密类型: %s", encryptionType)
	}

	if err != nil {
		log.Fatalf("加载或创建主机密钥失败: %v", err)
	}

	// 3. Create signer for ssh.ServerConfig
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

	// 4. Configure ssh.ServerConfig
	sshCfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == cfg.Auth.User && string(password) == cfg.Auth.Password {
				log.Printf("用户 '%s' 密码认证成功", conn.User())
				return nil, nil // Success
			}
			log.Printf("用户 '%s' 密码认证失败", conn.User())
			return nil, fmt.Errorf("密码错误") // Failure
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Define the path to the authorized_keys file
			// For simplicity, using a fixed base directory. This could be made configurable.
			authKeysDir := "./authorized_keys_store"
			// Ensure the base directory for authorized keys exists
			if _, err := os.Stat(authKeysDir); os.IsNotExist(err) {
				log.Printf("创建 authorized_keys 存储目录: %s", authKeysDir)
				if err := os.MkdirAll(authKeysDir, 0700); err != nil { // Read/Write/Execute for owner only
					log.Printf("创建 authorized_keys 存储目录 '%s' 失败: %v", authKeysDir, err)
					return nil, fmt.Errorf("无法创建 authorized_keys 存储目录")
				}
			}

			userAuthKeysFile := filepath.Join(authKeysDir, conn.User(), "authorized_keys")

			// Log the attempt
			log.Printf("用户 '%s' 尝试使用公钥类型 '%s' 进行认证 (来源: %s)", conn.User(), key.Type(), userAuthKeysFile)

			// Read the authorized_keys file
			authorizedKeysBytes, err := os.ReadFile(userAuthKeysFile)
			if err != nil {
				if os.IsNotExist(err) {
					log.Printf("用户的 authorized_keys 文件 '%s' 未找到", userAuthKeysFile)
					return nil, fmt.Errorf("authorized_keys 文件未找到")
				}
				log.Printf("读取 authorized_keys 文件 '%s' 失败: %v", userAuthKeysFile, err)
				return nil, fmt.Errorf("无法读取 authorized_keys 文件")
			}

			// Parse the authorized keys
			var authorizedKeys []ssh.PublicKey
			for len(authorizedKeysBytes) > 0 {
				pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
				if err != nil {
					log.Printf("解析 authorized_keys 文件 '%s' 中的密钥失败: %v", userAuthKeysFile, err)
					// Potentially skip this key and continue, or fail hard.
					// For now, let's be strict.
					return nil, fmt.Errorf("无法解析 authorized_keys 文件中的密钥")
				}
				authorizedKeys = append(authorizedKeys, pubKey)
				authorizedKeysBytes = rest
			}

			// Check if the provided public key is in the list of authorized keys
			for _, authorizedKey := range authorizedKeys {
				// Compare marshaled public key bytes
				if bytes.Equal(key.Marshal(), authorizedKey.Marshal()) {
					log.Printf("用户 '%s' 公钥认证成功 (类型: %s)", conn.User(), key.Type())
					return nil, nil // Success
				}
			}

			log.Printf("用户 '%s' 公钥认证失败: 提供的密钥不在 authorized_keys 文件中", conn.User())
			return nil, fmt.Errorf("公钥认证失败")
		},
	}
	sshCfg.AddHostKey(signer)

	// 5. Create SSHServer instance
	appServer := &server.SSHServer{
		Port:         cfg.Server.Port,
		Address:      cfg.Server.Host,
		Server:       sshCfg,
		EnableSftp:   cfg.Server.SftpEnabled,
		ReadOnlySftp: cfg.Server.SftpReadonly,
		// HostKey field removed from server.SSHServer as it was unused.
		// The ssh.ServerConfig (appServer.Server) already contains the host keys via AddHostKey().
	}

	// 6. Start the server
	log.Printf("SSH 服务器启动中，监听地址 %s:%d...", appServer.Address, appServer.Port)
	appServer.Start()
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
