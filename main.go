package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sshd/config"
	"sshd/server"
	"sshd/system"
	"strings"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
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

func main() {
	// 1. 加载配置
	cfg, err := config.LoadConfig(configFilePath)
	if err != nil {
		log.Fatalf("无法加载配置文件 '%s': %v", configFilePath, err)
	}

	// 2. 确定加密类型并加载或创建主机密钥
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

	// 3. 为 ssh.ServerConfig 创建签名者 (signer)
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

	// 4. 配置 ssh.ServerConfig
	sshCfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			// 检查是否启用了密码认证
			if !cfg.AuthSettings.PasswordAuthentication {
				log.Printf("密码认证被禁用 (用户: %s)", conn.User())
				return nil, fmt.Errorf("password authentication is disabled")
			}

			username := conn.User()
			// 检查 PermitRootLogin 对密码认证的限制
			if username == "root" &&
				(cfg.AuthSettings.PermitRootLogin == "no" || cfg.AuthSettings.PermitRootLogin == "prohibit-password") {
				log.Printf("Root 用户通过密码登录被拒绝 (PermitRootLogin: %s)", cfg.AuthSettings.PermitRootLogin)
				return nil, fmt.Errorf("root password login refused")
			}

			// 查找系统用户
			sysUser, err := system.LookupUser(username)
			if err != nil {
				log.Printf("密码认证失败: 系统用户 '%s' 未找到. %v", conn.User(), err)
				return nil, fmt.Errorf("password authentication failed: user not found or system error")
			}
			log.Printf("密码认证尝试: 系统用户 '%s' (UID: %s) 存在, 主目录: %s", sysUser.Username, sysUser.UID, sysUser.HomeDir)

			// 获取用户的 shadow 条目
			shadowEntry, err := system.GetShadowEntryForUser(sysUser.Username)
			if err != nil {
				log.Printf("密码认证失败: 无法获取用户 '%s' 的 shadow 条目: %v", sysUser.Username, err)
				return nil, fmt.Errorf("authentication failed: internal server error") // 对客户端返回通用错误
			}

			// 检查 shadow 条目中阻止登录的条件
			// 1. 空密码哈希 (用户可能未设置密码, 或密码由其他方式管理)
			// 2. 哈希为 '*' (账户锁定) 或 '!' (密码未设置/禁用) 或 '!!' (密码从未设置)
			// 其他前缀如 *LK* 或 *NP* 也可能存在.
			// 标准 `sshd` 通常将哈希开头为 `!` 或 `*` 视为不可登录.
			// 空哈希字段也表示无密码登录.
			if shadowEntry.PasswordHash == "" || strings.HasPrefix(shadowEntry.PasswordHash, "!") || strings.HasPrefix(shadowEntry.PasswordHash, "*") {
				log.Printf("密码认证失败: 用户 '%s' 账户已锁定或无密码登录权限 (shadow hash: '%s')", sysUser.Username, shadowEntry.PasswordHash)
				return nil, fmt.Errorf("password authentication failed: account locked or no password login")
			}

			// 执行基于时间的账户和密码过期检查
			// 所有计算均基于自纪元 (1970年1月1日) 以来的天数
			todayInDays := time.Now().Unix() / (60 * 60 * 24)

			// 检查账户过期
			if shadowEntry.ExpiryDate > 0 && todayInDays > shadowEntry.ExpiryDate {
				log.Printf("密码认证失败: 用户 '%s' 账户已于 %d 天前过期 (ExpiryDate: %d, Today: %d)",
					sysUser.Username, todayInDays-shadowEntry.ExpiryDate, shadowEntry.ExpiryDate, todayInDays)
				return nil, fmt.Errorf("password authentication failed: account expired")
			}

			// 检查密码过期 (如果设置了 MaxAge)
			// MaxAge 是密码有效的天数. LastChange 是上次更改密码的时间.
			if shadowEntry.MaxAge > 0 && shadowEntry.MaxAge < 99999 { // 99999 通常表示 "永不 किंवा"
				passwordExpiryDay := shadowEntry.LastChange + shadowEntry.MaxAge
				if todayInDays > passwordExpiryDay {
					log.Printf("密码认证失败: 用户 '%s' 的密码已于 %d 天前过期 (LastChange: %d, MaxAge: %d, ExpiryDay: %d, Today: %d)",
						sysUser.Username, todayInDays-passwordExpiryDay, shadowEntry.LastChange, shadowEntry.MaxAge, passwordExpiryDay, todayInDays)
					return nil, fmt.Errorf("password authentication failed: password expired")
				}

				// 检查警告期 (仅记录日志, 不拒绝登录)
				if shadowEntry.WarnPeriod > 0 {
					warnStartDate := passwordExpiryDay - shadowEntry.WarnPeriod
					if todayInDays >= warnStartDate {
						daysToExpiry := passwordExpiryDay - todayInDays
						log.Printf("提醒: 用户 '%s' 的密码将在 %d 天内过期", sysUser.Username, daysToExpiry)
						// 此信息如果 SSH 协议支持, 可以传递给客户端, 或记录供管理员查看. 目前仅作服务器日志.
					}
				}
			}
			// MinAge 检查: 如果需要, 可以检查 `todayInDays < shadowEntry.LastChange + shadowEntry.MinAge`
			// 并在密码更改过于频繁时阻止登录. sshd 通常不在登录时强制执行此操作.

			// 验证密码
			passwordMatch, err := system.VerifyPassword(string(password), shadowEntry.PasswordHash)
			if err != nil {
				// 此错误来自 system.VerifyPassword, 可能是哈希不受支持或其他内部错误
				log.Printf("密码认证错误: 用户 '%s' 密码校验时发生错误: %v", sysUser.Username, err)
				return nil, fmt.Errorf("authentication failed: password verification error")
			}

			if passwordMatch {
				log.Printf("用户 '%s' (系统用户 '%s') /etc/shadow 密码认证成功", conn.User(), sysUser.Username)
				return &ssh.Permissions{
					Extensions: map[string]string{
						"systemUserHome": sysUser.HomeDir,
						"systemUserUID":  sysUser.UID,
						"systemUserGID":  sysUser.GID,
						"systemUsername": sysUser.Username,
					},
				}, nil
			}

			log.Printf("用户 '%s' (系统用户 '%s') /etc/shadow 密码认证失败 (密码不匹配)", conn.User(), sysUser.Username)
			return nil, fmt.Errorf("incorrect password")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// 检查是否启用了公钥认证
			if !cfg.AuthSettings.PubkeyAuthentication {
				log.Printf("公钥认证被禁用 (用户: %s)", conn.User())
				return nil, fmt.Errorf("public key authentication is disabled")
			}

			username := conn.User()
			// 检查 PermitRootLogin 对公钥认证的限制
			if username == "root" && cfg.AuthSettings.PermitRootLogin == "no" {
				log.Printf("Root 用户通过公钥登录被拒绝 (PermitRootLogin: no)")
				return nil, fmt.Errorf("root public key login refused")
			}
			// 注意: PermitRootLogin 的 "prohibit-password" 选项明确允许 root 用户使用公钥登录, 因此此处无需检查.

			// 查找系统用户 (此处也需要获取主目录以查找 authorized_keys)
			sysUser, err := system.LookupUser(username)
			if err != nil {
				log.Printf("公钥认证失败: 系统用户 '%s' 未找到. %v", username, err)
				return nil, fmt.Errorf("public key authentication failed: user not found or system error")
			}
			log.Printf("公钥认证尝试: 系统用户 '%s' (UID: %s) 存在, 主目录: %s", sysUser.Username, sysUser.UID, sysUser.HomeDir)

			// 构建用户系统主目录中 authorized_keys 文件的路径
			if sysUser.HomeDir == "" {
				log.Printf("公钥认证失败: 系统用户 '%s' 的主目录未设置或无法访问", sysUser.Username)
				return nil, fmt.Errorf("user home directory not set or accessible")
			}
			userAuthKeysFile := filepath.Join(sysUser.HomeDir, ".ssh", "authorized_keys")

			log.Printf("尝试从系统用户 '%s' 的 '%s' 读取公钥", sysUser.Username, userAuthKeysFile)

			authorizedKeysBytes, err := os.ReadFile(userAuthKeysFile)
			if err != nil {
				if os.IsNotExist(err) {
					log.Printf("公钥认证失败: authorized_keys 文件 '%s' 未找到", userAuthKeysFile)
					return nil, fmt.Errorf("authorized_keys file not found or not accessible")
				}
				log.Printf("公钥认证失败: 读取 authorized_keys 文件 '%s' 失败: %v", userAuthKeysFile, err)
				return nil, fmt.Errorf("cannot read authorized_keys file")
			}

			// 解析 authorized_keys 文件内容
			var authorizedKeys []ssh.PublicKey
			for len(authorizedKeysBytes) > 0 {
				pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
				if err != nil {
					log.Printf("解析 authorized_keys 文件 '%s' 中的密钥失败: %v", userAuthKeysFile, err)
					// 可以考虑跳过此密钥并继续, 或直接失败.
					// 目前采取严格失败策略.
					return nil, fmt.Errorf("cannot parse key in authorized_keys file")
				}
				authorizedKeys = append(authorizedKeys, pubKey)
				authorizedKeysBytes = rest
			}

			// 检查提供的公钥是否存在于 authorized_keys 列表中
			for _, authorizedKey := range authorizedKeys {
				// 比较序列化后的公钥字节
				if bytes.Equal(key.Marshal(), authorizedKey.Marshal()) {
					log.Printf("用户 '%s' (系统用户 '%s') 公钥认证成功 (类型: %s)", conn.User(), sysUser.Username, key.Type())
					return &ssh.Permissions{
						Extensions: map[string]string{
							"systemUserHome": sysUser.HomeDir,
							"systemUserUID":  sysUser.UID,
							"systemUserGID":  sysUser.GID,
							"systemUsername": sysUser.Username,
						},
					}, nil // 成功
				}
			}

			log.Printf("用户 '%s' (系统用户 '%s') 公钥认证失败: 提供的密钥不在 authorized_keys 文件中", conn.User(), sysUser.Username)
			return nil, fmt.Errorf("public key authentication failed")
		},
	}
	sshCfg.AddHostKey(signer)

	// 5. 创建 SSHServer 实例
	appServer := &server.SSHServer{
		Port:         cfg.Server.Port,
		Address:      cfg.Server.Host,
		Server:       sshCfg,
		EnableSftp:   cfg.Server.SftpEnabled,
		ReadOnlySftp: cfg.Server.SftpReadonly,
	}

	// 6. 启动服务器
	log.Printf("SSH 服务器启动中，监听地址 %s:%d...", appServer.Address, appServer.Port)
	appServer.Start()
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
