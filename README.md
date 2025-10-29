# IPv6 Rotating Proxy Server

[English](#english) | [中文](#中文)

---

## English

### 🚀 Overview

A one-click installation script for setting up an IPv6 rotating proxy server with SOCKS5 and HTTP CONNECT support. Perfect for scenarios requiring automatic IP rotation and high-concurrency proxy services.

### ✨ Features

- **Dual Protocol Support**: SOCKS5 and HTTP CONNECT protocols
- **IPv6 Rotation**: Automatic rotation through IPv6 address pool (/64 subnet)
- **Authentication**: Username/password authentication for secure access
- **High Performance**: Built with Go for maximum concurrency and low latency
- **Monitoring**: Built-in metrics endpoint for service monitoring
- **Auto Cleanup**: Automatically removes conflicting services and processes
- **Systemd Integration**: Runs as a system service with auto-restart
- **Interactive Setup**: User-friendly installation wizard

### 📋 System Requirements

- **OS**: Ubuntu 20.04+ / Debian 10+ / CentOS 8+
- **Network**: IPv6 connectivity with /64 subnet
- **Privileges**: Root access
- **Memory**: 512MB+ RAM
- **Disk**: 100MB+ free space

### 🔧 Quick Installation

```bash
# Download the installation script
wget -O install.sh https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/install.sh

# Make it executable
chmod +x install.sh

# Run the installer
sudo ./install.sh
```

The script will:
1. Clean up any existing proxy services
2. Detect your server's IPv4 and IPv6 configuration
3. Guide you through interactive configuration
4. Install Go (if not present)
5. Compile and deploy the proxy server
6. Set up systemd service

### 📖 Usage

#### Basic Configuration

During installation, you'll be prompted for:
- **Proxy Port**: Default 20000
- **Metrics Port**: Default 20001
- **Username**: Default "proxy"
- **Password**: Auto-generated if not provided
- **IPv6 Rotation**: Enable/disable IPv6 rotation

#### Testing Your Proxy

**SOCKS5 Test:**
```bash
curl -x socks5://username:password@YOUR_IP:20000 http://ipv6.ip.sb
```

**HTTP Test:**
```bash
curl -x http://username:password@YOUR_IP:20000 http://ipv6.ip.sb
```

#### Service Management

```bash
# Check service status
systemctl status ipv6-proxy

# View logs
journalctl -u ipv6-proxy -f

# Restart service
systemctl restart ipv6-proxy

# Stop service
systemctl stop ipv6-proxy
```

#### Monitoring

```bash
# View metrics
curl http://localhost:20001/metrics

# Health check
curl http://localhost:20001/health
```

**Metrics Output:**
```
proxy_active 5        # Active connections
proxy_total 1234      # Total connections since start
proxy_success 1200    # Successful connections
proxy_failed 34       # Failed connections
```

### 🔐 Security Recommendations

1. **Change Default Credentials**: Always use strong passwords
2. **Firewall Rules**: Restrict proxy port access
   ```bash
   ufw allow from YOUR_IP to any port 20000
   ```
3. **Regular Updates**: Keep system and Go runtime updated
4. **Monitor Usage**: Check logs regularly for suspicious activity
5. **Use HTTPS**: For web proxy requests when possible

### 🏗️ Architecture

```
Client Request
    ↓
[SOCKS5/HTTP Handler]
    ↓
[Authentication Check]
    ↓
[Random IPv6 Selection] (/64 pool)
    ↓
[Outbound Connection] (with selected IPv6)
    ↓
[Bidirectional Relay]
    ↓
Target Server
```

### 📊 Performance

- **Concurrency**: Supports 10,000+ concurrent connections
- **Latency**: <5ms additional overhead
- **Throughput**: Limited only by network bandwidth
- **IPv6 Pool**: 18 quintillion addresses per /64 subnet

### 🛠️ Manual Configuration

Configuration file location: `/etc/ipv6-proxy/config.txt`

```bash
PROXY_PORT=20000
METRICS_PORT=20001
USERNAME=proxy
PASSWORD=your_password
IPV6_ENABLED=true
IPV6_PREFIX=2001:db8:1234:5678
```

After editing, restart the service:
```bash
systemctl restart ipv6-proxy
```

### 🐛 Troubleshooting

**Port already in use:**
```bash
# The script handles this, but if needed:
lsof -i :20000
kill -9 <PID>
```

**IPv6 not working:**
```bash
# Test IPv6 connectivity
ping6 2001:4860:4860::8888

# Check IPv6 addresses
ip -6 addr show
```

**Service won't start:**
```bash
# Check detailed logs
journalctl -u ipv6-proxy -n 50 --no-pager
```

### 📝 Configuration Examples

**Example 1: Basic HTTP Proxy (with IPv6)**
```bash
# In your application
export http_proxy="http://username:password@YOUR_IP:20000"
export https_proxy="http://username:password@YOUR_IP:20000"
```

**Example 2: SOCKS5 with curl**
```bash
curl --socks5 YOUR_IP:20000 --proxy-user username:password http://example.com
```

**Example 3: Python requests**
```python
import requests

proxies = {
    'http': 'socks5://username:password@YOUR_IP:20000',
    'https': 'socks5://username:password@YOUR_IP:20000'
}

response = requests.get('http://ipv6.ip.sb', proxies=proxies)
print(response.text)
```

### 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### 📜 License

MIT License - see [LICENSE](LICENSE) file for details

### ⚠️ Disclaimer

This software is provided for educational and legitimate use cases only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse.

### 📮 Support

- **Issues**: [GitHub Issues](https://github.com/kenanjun001/ipv6-rotating-proxy/issues)
- **Wiki**: [Documentation](https://github.com/kenanjun001/ipv6-rotating-proxy/wiki)

---

## 中文

### 🚀 项目简介

一键安装脚本，用于部署支持 IPv6 轮换的代理服务器，同时支持 SOCKS5 和 HTTP CONNECT 协议。适用于需要自动 IP 轮换和高并发代理服务的场景。

### ✨ 功能特性

- **双协议支持**：SOCKS5 和 HTTP CONNECT 协议
- **IPv6 轮换**：自动在 IPv6 地址池中轮换（/64 子网）
- **用户认证**：用户名/密码认证保障安全访问
- **高性能**：Go 语言开发，支持高并发低延迟
- **监控接口**：内置监控端点，实时查看服务状态
- **自动清理**：自动清理冲突的服务和进程
- **系统集成**：作为 systemd 服务运行，支持自动重启
- **交互式安装**：友好的安装向导

### 📋 系统要求

- **操作系统**：Ubuntu 20.04+ / Debian 10+ / CentOS 8+
- **网络**：支持 IPv6 且有 /64 子网
- **权限**：Root 权限
- **内存**：512MB+ RAM
- **磁盘**：100MB+ 可用空间

### 🔧 快速安装

```bash
# 下载安装脚本
wget -O install.sh https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/install.sh

# 添加执行权限
chmod +x install.sh

# 运行安装程序
sudo ./install.sh
```

脚本将自动完成：
1. 清理现有的代理服务
2. 检测服务器的 IPv4 和 IPv6 配置
3. 交互式配置向导
4. 安装 Go（如果未安装）
5. 编译并部署代理服务器
6. 设置 systemd 服务

### 📖 使用说明

#### 基础配置

安装过程中会提示输入：
- **代理端口**：默认 20000
- **监控端口**：默认 20001
- **用户名**：默认 "proxy"
- **密码**：如果不输入将自动生成
- **IPv6 轮换**：启用/禁用 IPv6 轮换

#### 测试代理

**SOCKS5 测试：**
```bash
curl -x socks5://用户名:密码@你的IP:20000 http://ipv6.ip.sb
```

**HTTP 测试：**
```bash
curl -x http://用户名:密码@你的IP:20000 http://ipv6.ip.sb
```

#### 服务管理

```bash
# 查看服务状态
systemctl status ipv6-proxy

# 查看日志
journalctl -u ipv6-proxy -f

# 重启服务
systemctl restart ipv6-proxy

# 停止服务
systemctl stop ipv6-proxy
```

#### 监控服务

```bash
# 查看监控指标
curl http://localhost:20001/metrics

# 健康检查
curl http://localhost:20001/health
```

**监控输出示例：**
```
proxy_active 5        # 当前活跃连接数
proxy_total 1234      # 总连接数
proxy_success 1200    # 成功连接数
proxy_failed 34       # 失败连接数
```

### 🔐 安全建议

1. **修改默认密码**：始终使用强密码
2. **防火墙规则**：限制代理端口访问
   ```bash
   ufw allow from 你的IP to any port 20000
   ```
3. **定期更新**：保持系统和 Go 运行时更新
4. **监控使用**：定期检查日志，发现异常活动
5. **使用 HTTPS**：尽可能使用 HTTPS 进行代理请求

### 🏗️ 架构设计

```
客户端请求
    ↓
[SOCKS5/HTTP 处理器]
    ↓
[身份验证检查]
    ↓
[随机 IPv6 选择] (/64 地址池)
    ↓
[出站连接] (使用选定的 IPv6)
    ↓
[双向数据转发]
    ↓
目标服务器
```

### 📊 性能指标

- **并发能力**：支持 10,000+ 并发连接
- **延迟**：额外开销 <5ms
- **吞吐量**：仅受网络带宽限制
- **IPv6 池**：每个 /64 子网有 18 quintillion 个地址

### 🛠️ 手动配置

配置文件位置：`/etc/ipv6-proxy/config.txt`

```bash
PROXY_PORT=20000
METRICS_PORT=20001
USERNAME=proxy
PASSWORD=your_password
IPV6_ENABLED=true
IPV6_PREFIX=2001:db8:1234:5678
```

修改后重启服务：
```bash
systemctl restart ipv6-proxy
```

### 🐛 故障排查

**端口已被占用：**
```bash
# 脚本会自动处理，但如需手动操作：
lsof -i :20000
kill -9 <PID>
```

**IPv6 不工作：**
```bash
# 测试 IPv6 连接
ping6 2001:4860:4860::8888

# 检查 IPv6 地址
ip -6 addr show
```

**服务无法启动：**
```bash
# 查看详细日志
journalctl -u ipv6-proxy -n 50 --no-pager
```

### 📝 配置示例

**示例 1：基础 HTTP 代理（带 IPv6）**
```bash
# 在你的应用中
export http_proxy="http://用户名:密码@你的IP:20000"
export https_proxy="http://用户名:密码@你的IP:20000"
```

**示例 2：curl 使用 SOCKS5**
```bash
curl --socks5 你的IP:20000 --proxy-user 用户名:密码 http://example.com
```

**示例 3：Python requests**
```python
import requests

proxies = {
    'http': 'socks5://用户名:密码@你的IP:20000',
    'https': 'socks5://用户名:密码@你的IP:20000'
}

response = requests.get('http://ipv6.ip.sb', proxies=proxies)
print(response.text)
```

### 🤝 贡献

欢迎贡献！请随时提交 Pull Request。

### 📜 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

### ⚠️ 免责声明

本软件仅供教育和合法用途使用。用户有责任遵守所有适用的法律法规。作者对滥用行为不承担任何责任。

### 📮 支持

- **问题反馈**：[GitHub Issues](https://github.com/kenanjun001/ipv6-rotating-proxy/issues)
- **文档**：[Wiki](https://github.com/kenanjun001/ipv6-rotating-proxy/wiki)

---

### 🌟 Star History

如果这个项目对你有帮助，请给个 Star ⭐️

### 📈 Roadmap

- [ ] 支持 Docker 部署
- [ ] Web 管理面板
- [ ] 多服务器负载均衡
- [ ] 流量统计可视化
- [ ] API 管理接口

---

**Made with ❤️ for the open source community**
