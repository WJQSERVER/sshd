# SSHD Server in Go

**注意: 本项目目前为一个实验性/可行性研究项目, 可能不适用于生产环境. 请谨慎评估其稳定性和安全性.**

这是一个使用 Go 语言实现的 SSHD (Secure Shell Daemon) 服务器. 它旨在提供一个安全、可配置且可扩展的 SSH 服务端解决方案.

## 功能特性

*   **标准 SSH 协议支持**: 基于 `golang.org/x/crypto/ssh` 实现, 支持 SSH2 协议.
*   **多种认证方式**:
    *   **密码认证**: 通过系统 `/etc/shadow` (或配置的 PAM 服务, 如果系统支持并配置)进行用户密码验证.
    *   **公钥认证**: 支持标准的 `~/.ssh/authorized_keys` 文件进行公钥验证.
*   **PTY 与 Shell**: 为交互式会话提供伪终端 (PTY) 支持和 Shell 访问.
*   **SFTP 支持**: 内置 SFTP 服务器功能, 允许文件传输. 可配置为只读或读写模式.
*   **主机密钥管理**: 自动加载现有的主机密钥, 或在首次启动时生成新的主机密钥 (支持 ed25519, RSA 等).
*   **灵活配置**: 通过 `config.toml` 文件进行详细配置, 包括监听地址、端口、认证选项、SFTP 设置等.
*   **认证中间件框架**:
    *   提供了一个可扩展的认证中间件框架, 允许在核心认证逻辑执行前后注入自定义处理逻辑 (如日志、限流、IP过滤等).
    *   通过 `AuthContext` 在中间件链中传递认证上下文.
*   **内置 Fail2Ban 中间件**:
    *   作为中间件框架的应用, 内置了 Fail2Ban 功能, 可自动阻止多次登录失败的 IP 地址.
    *   参数可配置 (最大尝试次数、查找时间、封禁时间、白名单等).
    *   自动清理过期数据以管理内存.

## 快速开始

### 构建

确保你已安装 Go (推荐版本 1.18 或更高).

```bash
git clone [你的项目仓库地址]
cd [项目目录]
go build -o mysshd .
```

### 配置

服务器在首次启动时, 如果在指定路径 (默认为 `./config/config.toml`) 未找到配置文件, 将会自动创建一个包含默认设置的 `config.toml` 文件.

请根据你的需求修改 `config.toml`. 以下是一些关键配置项:

*   **服务器基本设置 (`[server]`)**:
    *   `host`: 监听的主机 IP (例如 "0.0.0.0" 表示所有接口).
    *   `port`: 监听的端口 (例如 2200).
    *   `cert`: 主机密钥类型 (例如 "ed25519", "rsa").
    *   `sftp_enabled`: 是否启用 SFTP.
    *   `sftp_readonly`: SFTP 是否为只读模式.

*   **认证设置 (`[auth_settings]`)**:
    *   `password_authentication`: 是否允许密码认证.
    *   `pubkey_authentication`: 是否允许公钥认证.
    *   `permit_root_login`: Root 用户登录策略 (例如 "yes", "no", "prohibit-password").

*   **Fail2Ban 设置 (`[fail2ban]`)**:
    *   `enabled`: 是否启用 Fail2Ban (布尔值, 例如 `true`).
    *   `max_attempts`: 封禁前的最大失败尝试次数 (整数, 例如 `5`).
    *   `find_time`: 评估失败尝试的时间窗口 (字符串, 例如 `"10m"` 表示10分钟, `"1h"` 表示1小时).
    *   `ban_time`: IP 被封禁的时长 (字符串, 例如 `"30m"`, `"24h"`).
    *   `whitelist`: IP 地址或 CIDR 白名单列表 (字符串数组, 例如 `["127.0.0.1/32", "::1/128", "192.168.1.0/24"]`).

**示例 `config.toml` 片段**:
```toml
[server]
host = "0.0.0.0"
port = 2200
cert = "ed25519"
sftp_enabled = true
sftp_readonly = false

[auth_settings]
password_authentication = true
pubkey_authentication = true
permit_root_login = "prohibit-password"

[fail2ban]
enabled = true
max_attempts = 3
find_time = "5m"
ban_time = "1h"
whitelist = ["192.168.1.0/24", "10.0.0.1"]
```

### 运行

```bash
./sshd -c /path/to/your/config.toml
```
如果不指定 `-c` 参数, 服务器会尝试从当前目录加载 `./config/config.toml`.

## 内部实现亮点

### 认证中间件
服务器的认证流程通过一个中间件链进行处理. 每个中间件都可以检查和修改认证上下文 (`AuthContext`), 并决定是否将请求传递给下一个中间件或核心认证逻辑. 这种设计使得添加新的认证相关功能 (如日志、双因素认证前置检查、自定义 IP 过滤等) 变得更加容易和模块化.

`Fail2Ban` 功能就是作为这样一个中间件实现的, 它在核心的密码或公钥验证之前检查请求来源 IP 的状态.

## 贡献

由于本项目目前为实验性研究, 贡献方式可能有所不同. 如果您有改进建议或发现了问题, 欢迎通过创建 Issue 来讨论.

## 许可证

本项目采用 **Mozilla Public License Version 2.0 (MPL-2.0)** 授权.
完整的许可证文本可以在项目根目录下的 `LICENSE` 文件中找到, 或者访问 [https://mozilla.org/MPL/2.0/](https://mozilla.org/MPL/2.0/).

MPL-2.0 是一个具有 copyleft 特性的自由软件许可证, 它试图在鼓励代码共享和允许与非开源代码集成之间取得平衡.