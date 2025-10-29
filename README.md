# IPv6 Rotating Proxy Server - 多端口版本

[中文](#中文) | [English](#english)

---

## 中文

### 🚀 项目简介

一键安装脚本,用于部署支持 IPv6 轮换的代理服务器,同时支持 SOCKS5 和 HTTP CONNECT 协议。**支持创建 1-100000 个代理端口,1个进程管理所有端口**。

### ✨ 核心特性

- **🎯 大规模端口**: 1个Go进程监听 1-100000 个端口
- **⚡ IPv6随机轮换**: 每个端口每次请求使用不同的 IPv6 地址
- **🔐 双协议支持**: SOCKS5 和 HTTP CONNECT
- **📊 统一监控**: 所有端口的连接统计和流量监控
- **💪 高性能**: 10000端口仅占用 ~200MB 内存
- **🔧 交互配置**: 自定义端口数量和起始端口
- **🛡️ 系统优化**: 自动调整内核参数和文件描述符
- **🚀 无限制模式**: 默认配置支持百万级并发,文件描述符无限制

### 📋 系统要求

- **操作系统**: Ubuntu 20.04+ / Debian 10+ / CentOS 8+
- **网络**: IPv6 支持 + /64 子网
- **CPU**: 2核+ (推荐 4核+)
- **内存**: 1GB+ (10000端口建议 2GB+)
- **权限**: Root

### 🔧 快速安装

```bash
# 1. 下载安装脚本
wget -O install.sh https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/install.sh

# 2. 添加执行权限
chmod +x install.sh

# 3. 运行安装
sudo ./install.sh
```

### 🔄 一键更新

```bash
# 重新运行安装脚本即可更新(保留配置)
wget -O install.sh https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

**更多更新方式**: 查看 [UPDATE.md](UPDATE.md)

### 📝 安装示例

```
检测到 IPv4: 123.45.67.89
确认使用此IP? [Y/n] ↵

检测到 IPv6: 2001:db8:1234:5678::/64
启用 IPv6 随机轮换? [Y/n] ↵

创建多少个代理端口? [1000]: 10000
起始端口号? [20000]: 20000
监控端口 [10001]: ↵
用户名 [proxy]: ↵
密码 [回车自动生成]: ↵
生成密码: a1b2c3d4e5f6

配置摘要:
服务器 IP: 123.45.67.89
代理数量: 10000 个
端口范围: 20000 - 29999
监控端口: 10001
用户名: proxy
密码: a1b2c3d4e5f6
IPv6轮换: 启用 (2001:db8:1234:5678::/64)

确认安装? [Y/n] ↵

✓ 正在启动 10000 个代理端口...
✓ 进度: 10000/10000 (100.0%)
✓ 启动完成! 成功: 10000 | 失败: 0
```

### 🧪 测试代理

#### 测试单个端口

```bash
# SOCKS5
curl -x socks5://proxy:a1b2c3d4e5f6@123.45.67.89:20000 http://ipv6.ip.sb

# HTTP
curl -x http://proxy:a1b2c3d4e5f6@123.45.67.89:20000 http://ipv6.ip.sb
```

#### 测试多个端口

```bash
# 测试前10个端口
for port in {20000..20009}; do
    echo "测试端口 $port:"
    curl -s -x http://proxy:password@123.45.67.89:$port http://ipv6.ip.sb
done
```

#### 验证 IPv6 轮换

```bash
# 同一端口,每次请求返回不同的 IPv6
for i in {1..5}; do
    curl -s -x http://proxy:password@123.45.67.89:20000 http://ipv6.ip.sb
done
```

输出示例:
```
2001:db8:1234:5678:a3f2:8901:4567:abcd
2001:db8:1234:5678:f821:2345:6789:0123
2001:db8:1234:5678:1234:5678:9abc:def0
2001:db8:1234:5678:8765:4321:fedc:ba98
2001:db8:1234:5678:5a5a:b6b6:c7c7:d8d8
```

### 📊 监控服务

#### 查看统计信息

```bash
curl http://localhost:10001/metrics
```

输出:
```
proxy_ports_total 10000           # 总端口数
proxy_ports_success 10000         # 成功启动的端口
proxy_ports_failed 0              # 失败的端口
proxy_active_conns 1234           # 当前活跃连接
proxy_total_conns 567890          # 总连接数
proxy_success_conns 560000        # 成功连接
proxy_failed_conns 7890           # 失败连接
proxy_bytes_in 12500000000        # 入站流量(字节)
proxy_bytes_out 45300000000       # 出站流量(字节)
```

#### 服务管理

```bash
# 查看服务状态
systemctl status ipv6-proxy

# 查看实时日志
journalctl -u ipv6-proxy -f

# 重启服务
systemctl restart ipv6-proxy

# 停止服务
systemctl stop ipv6-proxy

# 启动服务
systemctl start ipv6-proxy
```

#### 更新服务

```bash
# 方法1: 重新运行安装脚本(推荐)
wget -O install.sh https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/install.sh
chmod +x install.sh
sudo ./install.sh

# 方法2: 手动更新代码
cd /opt/ipv6-proxy
wget -O main.go https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/main.go
go build -ldflags="-s -w" -o ipv6-proxy main.go
systemctl restart ipv6-proxy

# 方法3: Git 更新(如果使用 Git)
cd /opt/ipv6-proxy
git pull
go build -ldflags="-s -w" -o ipv6-proxy main.go
systemctl restart ipv6-proxy
```

### 💻 代码示例

#### Python - 单代理

```python
import requests

proxies = {
    'http': 'http://proxy:password@123.45.67.89:20000',
    'https': 'http://proxy:password@123.45.67.89:20000'
}

# 每次请求自动使用不同的 IPv6
response = requests.get('http://ipv6.ip.sb', proxies=proxies)
print(response.text)
```

#### Python - 代理池轮询

```python
import requests
import random

# 代理池: 10000个端口
PROXY_POOL = [
    {'http': f'http://proxy:password@123.45.67.89:{port}'}
    for port in range(20000, 30000)
]

# 每次请求使用不同端口
for i in range(100):
    proxy = random.choice(PROXY_POOL)
    response = requests.get('http://httpbin.org/ip', proxies=proxy)
    print(f"请求 {i+1}: {response.json()}")
```

#### Python - 并发爬虫

```python
import requests
from concurrent.futures import ThreadPoolExecutor
import random

PROXY_POOL = [f'http://proxy:pass@ip:{p}' for p in range(20000, 30000)]

def fetch(url):
    proxy = random.choice(PROXY_POOL)
    response = requests.get(url, proxies={'http': proxy, 'https': proxy})
    return response.text

urls = ['http://example.com/page1', 'http://example.com/page2'] * 100

# 200个并发请求
with ThreadPoolExecutor(max_workers=200) as executor:
    results = list(executor.map(fetch, urls))
    
print(f"完成 {len(results)} 个请求")
```

### ⚙️ 配置文件

位置: `/etc/ipv6-proxy/config.txt`

```bash
START_PORT=20000              # 起始端口
PORT_COUNT=10000              # 端口数量
METRICS_PORT=10001            # 监控端口
USERNAME=proxy                # 用户名
PASSWORD=your_password        # 密码
IPV6_ENABLED=true             # 启用IPv6轮换
IPV6_PREFIX=2001:db8:1234:5678  # IPv6前缀
```

修改配置后重启服务:
```bash
systemctl restart ipv6-proxy
```

### 📈 性能参考

| 端口数量 | 内存占用 | CPU(空闲) | 启动时间 | 并发能力 |
|---------|---------|-----------|---------|---------|
| 100 | ~20MB | <1% | <1秒 | 10万+ |
| 1,000 | ~50MB | <2% | ~2秒 | 100万+ |
| 10,000 | ~200MB | <5% | ~5秒 | 1000万+ |
| 50,000 | ~800MB | <10% | ~15秒 | 5000万+ |

### ⚡ 优化特性

**自动系统优化** (默认启用):
```
文件描述符: infinity (无限制)
进程数限制: infinity (无限制)
最大文件数: 10,000,000
连接跟踪: 10,000,000
TCP优化: 自动调整窗口和缓冲区
```

**支持场景**:
- ✅ 百万级并发连接
- ✅ 超大规模爬虫
- ✅ 高负载代理服务
- ✅ 长时间稳定运行
- ✅ 不会出现 "too many open files" 错误

### 🐛 故障排查

#### 端口被占用

如果端口被占用,Go程序会在日志中显示:
```bash
journalctl -u ipv6-proxy -f
# 输出: 端口 20000 启动失败: address already in use
```

手动清理端口:
```bash
# 查看占用
lsof -i :20000-29999

# 批量清理
lsof -ti :20000-29999 | xargs kill -9
```

#### IPv6 不工作

```bash
# 测试 IPv6 连通性
ping6 -c 3 2001:4860:4860::8888

# 检查 IPv6 地址
ip -6 addr show

# 测试特定 IPv6
curl --interface 2001:db8::1 http://ipv6.ip.sb
```

#### 修改端口数量

```bash
# 编辑配置
nano /etc/ipv6-proxy/config.txt

# 修改这两行
PORT_COUNT=5000
START_PORT=20000

# 重启服务
systemctl restart ipv6-proxy
```

### 🔐 安全建议

1. **强密码**: 使用至少 16 位随机字符
2. **防火墙**: 限制允许的 IP 访问
   ```bash
   ufw allow from 你的IP/32 to any port 20000:29999 proto tcp
   ```
3. **定期更新**: 保持系统最新
4. **监控日志**: 检测异常流量
   ```bash
   journalctl -u ipv6-proxy -f
   ```

### 💡 常见问题

**Q: 为什么需要这么多端口?**  
A: 每个端口可以独立分配给不同用户/应用,实现流量隔离和独立统计。

**Q: 每个端口的 IP 是固定的吗?**  
A: 不是。每个端口在每次请求时都会从 /64 子网随机选择一个 IPv6 地址。

**Q: 最多支持多少端口?**  
A: 理论上支持 1-65535,建议根据服务器配置选择 1000-50000。

**Q: CPU 占用高怎么办?**  
A: CPU 占用主要取决于请求量,不是端口数量。可以增加 CPU 核心或限流。

### 📞 支持

- **Telegram**: [@KN_001](https://t.me/KN_001)
- **Telegram群组**: [https://t.me/Oraclesu](https://t.me/Oraclesu)
- **问题反馈**: [GitHub Issues](https://github.com/kenanjun001/ipv6-rotating-proxy/issues)

---

## English

### 🚀 Overview

A one-click installation script for setting up an IPv6 rotating proxy server with SOCKS5 and HTTP CONNECT support. **Supports 1-100,000 proxy ports managed by a single process**.

### ✨ Key Features

- **🎯 Massive Scale**: Single Go process handles 1-100,000 ports
- **⚡ IPv6 Rotation**: Each port uses different IPv6 per request
- **🔐 Dual Protocol**: SOCKS5 and HTTP CONNECT support
- **📊 Unified Monitoring**: Connection stats and traffic for all ports
- **💪 High Performance**: Only ~200MB RAM for 10,000 ports
- **🔧 Interactive Setup**: Customize port count and starting port
- **🛡️ System Optimization**: Auto-tunes kernel parameters
- **🚀 Unlimited Mode**: Default config supports million-level concurrency, no file descriptor limits

### 📋 System Requirements

- **OS**: Ubuntu 20.04+ / Debian 10+ / CentOS 8+
- **Network**: IPv6 with /64 subnet
- **CPU**: 2+ cores (4+ recommended)
- **Memory**: 1GB+ (2GB+ for 10,000 ports)
- **Privileges**: Root access

### 🔧 Quick Installation

```bash
# 1. Download installation script
wget -O install.sh https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/install.sh

# 2. Make executable
chmod +x install.sh

# 3. Run installer
sudo ./install.sh
```

### 🔄 One-Click Update

```bash
# Re-run the installation script to update (keeps configuration)
wget -O install.sh https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

**More update methods**: See [UPDATE.md](UPDATE.md)

### 📝 Installation Example

```
Detected IPv4: 123.45.67.89
Confirm? [Y/n] ↵

Detected IPv6: 2001:db8:1234:5678::/64
Enable IPv6 rotation? [Y/n] ↵

How many proxy ports? [1000]: 10000
Starting port? [20000]: 20000
Metrics port [10001]: ↵
Username [proxy]: ↵
Password [auto-generate]: ↵
Generated password: a1b2c3d4e5f6

Configuration Summary:
Server IP: 123.45.67.89
Proxy count: 10000
Port range: 20000 - 29999
Metrics port: 10001
Username: proxy
Password: a1b2c3d4e5f6
IPv6 rotation: Enabled (2001:db8:1234:5678::/64)

Confirm installation? [Y/n] ↵

✓ Starting 10000 proxy ports...
✓ Progress: 10000/10000 (100.0%)
✓ Startup complete! Success: 10000 | Failed: 0
```

### 🧪 Testing

#### Test Single Port

```bash
# SOCKS5
curl -x socks5://proxy:password@123.45.67.89:20000 http://ipv6.ip.sb

# HTTP
curl -x http://proxy:password@123.45.67.89:20000 http://ipv6.ip.sb
```

#### Test Multiple Ports

```bash
# Test first 10 ports
for port in {20000..20009}; do
    echo "Testing port $port:"
    curl -s -x http://proxy:password@123.45.67.89:$port http://ipv6.ip.sb
done
```

#### Verify IPv6 Rotation

```bash
# Same port, different IPv6 each request
for i in {1..5}; do
    curl -s -x http://proxy:password@123.45.67.89:20000 http://ipv6.ip.sb
done
```

Output:
```
2001:db8:1234:5678:a3f2:8901:4567:abcd
2001:db8:1234:5678:f821:2345:6789:0123
2001:db8:1234:5678:1234:5678:9abc:def0
2001:db8:1234:5678:8765:4321:fedc:ba98
2001:db8:1234:5678:5a5a:b6b6:c7c7:d8d8
```

### 📊 Monitoring

#### View Statistics

```bash
curl http://localhost:10001/metrics
```

Output:
```
proxy_ports_total 10000           # Total ports
proxy_ports_success 10000         # Successfully started
proxy_ports_failed 0              # Failed to start
proxy_active_conns 1234           # Active connections
proxy_total_conns 567890          # Total connections
proxy_success_conns 560000        # Successful connections
proxy_failed_conns 7890           # Failed connections
proxy_bytes_in 12500000000        # Inbound traffic (bytes)
proxy_bytes_out 45300000000       # Outbound traffic (bytes)
```

#### Service Management

```bash
# Check status
systemctl status ipv6-proxy

# View live logs
journalctl -u ipv6-proxy -f

# Restart service
systemctl restart ipv6-proxy

# Stop service
systemctl stop ipv6-proxy

# Start service
systemctl start ipv6-proxy
```

#### Update Service

```bash
# Method 1: Re-run installation script (Recommended)
wget -O install.sh https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/install.sh
chmod +x install.sh
sudo ./install.sh

# Method 2: Manual code update
cd /opt/ipv6-proxy
wget -O main.go https://raw.githubusercontent.com/kenanjun001/ipv6-rotating-proxy/main/main.go
go build -ldflags="-s -w" -o ipv6-proxy main.go
systemctl restart ipv6-proxy

# Method 3: Git update (if using Git)
cd /opt/ipv6-proxy
git pull
go build -ldflags="-s -w" -o ipv6-proxy main.go
systemctl restart ipv6-proxy
```

### 💻 Code Examples

#### Python - Single Proxy

```python
import requests

proxies = {
    'http': 'http://proxy:password@123.45.67.89:20000',
    'https': 'http://proxy:password@123.45.67.89:20000'
}

# Different IPv6 each request
response = requests.get('http://ipv6.ip.sb', proxies=proxies)
print(response.text)
```

#### Python - Proxy Pool

```python
import requests
import random

# Pool of 10,000 ports
PROXY_POOL = [
    {'http': f'http://proxy:password@123.45.67.89:{port}'}
    for port in range(20000, 30000)
]

# Use different port each request
for i in range(100):
    proxy = random.choice(PROXY_POOL)
    response = requests.get('http://httpbin.org/ip', proxies=proxy)
    print(f"Request {i+1}: {response.json()}")
```

### ⚙️ Configuration

Location: `/etc/ipv6-proxy/config.txt`

```bash
START_PORT=20000              # Starting port
PORT_COUNT=10000              # Number of ports
METRICS_PORT=10001            # Metrics port
USERNAME=proxy                # Username
PASSWORD=your_password        # Password
IPV6_ENABLED=true             # Enable IPv6 rotation
IPV6_PREFIX=2001:db8:1234:5678  # IPv6 prefix
```

Restart after changes:
```bash
systemctl restart ipv6-proxy
```

### 📈 Performance

| Port Count | Memory | CPU (idle) | Startup | Concurrency |
|-----------|--------|------------|---------|-------------|
| 100 | ~20MB | <1% | <1s | 100k+ |
| 1,000 | ~50MB | <2% | ~2s | 1M+ |
| 10,000 | ~200MB | <5% | ~5s | 10M+ |
| 50,000 | ~800MB | <10% | ~15s | 50M+ |

### ⚡ Optimization Features

**Auto System Tuning** (enabled by default):
```
File Descriptors: infinity (unlimited)
Process Limit: infinity (unlimited)
Max Files: 10,000,000
Connection Tracking: 10,000,000
TCP Optimization: Auto-tuned windows and buffers
```

**Supported Scenarios**:
- ✅ Million-level concurrent connections
- ✅ Massive-scale web scraping
- ✅ High-load proxy services
- ✅ Long-term stable operation
- ✅ No "too many open files" errors

### 🐛 Troubleshooting

#### Port Already in Use

Check logs:
```bash
journalctl -u ipv6-proxy -f
# Output: Port 20000 startup failed: address already in use
```

Manual cleanup:
```bash
# Check usage
lsof -i :20000-29999

# Batch cleanup
lsof -ti :20000-29999 | xargs kill -9
```

#### IPv6 Not Working

```bash
# Test connectivity
ping6 -c 3 2001:4860:4860::8888

# Check addresses
ip -6 addr show

# Test specific IPv6
curl --interface 2001:db8::1 http://ipv6.ip.sb
```

### 🔐 Security

1. **Strong Password**: Use 16+ random characters
2. **Firewall**: Restrict IP access
   ```bash
   ufw allow from YOUR_IP/32 to any port 20000:29999 proto tcp
   ```
3. **Regular Updates**: Keep system updated
4. **Monitor Logs**: Check for anomalies
   ```bash
   journalctl -u ipv6-proxy -f
   ```

### 💡 FAQ

**Q: Why so many ports?**  
A: Each port can be assigned to different users/apps for traffic isolation.

**Q: Is the IP fixed per port?**  
A: No. Each port randomly selects an IPv6 from /64 subnet per request.

**Q: Maximum supported ports?**  
A: Theoretically 1-65535, recommended 1000-50000 based on hardware.

**Q: High CPU usage?**  
A: CPU depends on request volume, not port count. Scale up or rate-limit.

### 📞 Support

- **Telegram**: [@KN_001](https://t.me/KN_001)
- **Telegram Group**: [https://t.me/Oraclesu](https://t.me/Oraclesu)
- **Issues**: [GitHub Issues](https://github.com/kenanjun001/ipv6-rotating-proxy/issues)

---

### 🌟 Star History

If this project helps you, please give it a star ⭐

### 📜 License

MIT License - see [LICENSE](LICENSE) file for details

---

**Made with ❤️ for the open source community**
