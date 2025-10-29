#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

clear
echo ""
echo "========================================="
echo "  IPv6 Rotating Proxy - SNAT 方案"
echo "  ✅ ip6tables SNAT 规则"
echo "  ✅ 每端口固定 IPv6"
echo "  ✅ 自动定时清理"
echo "  ✅ 无需 ndppd"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    print_error "请使用 root 权限运行"
    exit 1
fi

# ==================== 清理 ====================
print_info "清理现有服务..."

for service in go-proxy ipv6-proxy ipv6-proxy-multi dynamic-proxy python-proxy ndppd ipv6-cleanup; do
    systemctl stop $service 2>/dev/null || true
    systemctl disable $service 2>/dev/null || true
    rm -f /etc/systemd/system/$service.service
done

systemctl daemon-reload
pkill -9 -f "ipv6-proxy" 2>/dev/null || true
pkill -9 -f "ndppd" 2>/dev/null || true

# 清理旧的 iptables 规则
ip6tables -t nat -F 2>/dev/null || true
ip6tables -t nat -X 2>/dev/null || true

print_success "清理完成"
echo ""

# ==================== 配置 ====================
print_info "配置参数..."
echo ""

# IPv4
IPV4=$(curl -s -4 --max-time 3 ifconfig.me 2>/dev/null || echo "")
if [ -z "$IPV4" ]; then
    read -p "请输入服务器 IPv4: " IPV4
else
    print_success "检测到 IPv4: $IPV4"
    read -p "确认? [Y/n] " confirm
    [[ $confirm =~ ^[Nn]$ ]] && read -p "请输入 IPv4: " IPV4
fi

# IPv6
USE_IPV6=false
IPV6_PREFIX=""
IPV6_INTERFACE=""

if ping6 -c 1 -W 2 2001:4860:4860::8888 &>/dev/null; then
    # 方法1: 使用 ip 命令（推荐）
    if command -v ip &>/dev/null; then
        IFACE_LINE=$(ip -6 addr show scope global 2>/dev/null | grep -E "^[0-9]+:" | head -1)
        if [ -n "$IFACE_LINE" ]; then
            IPV6_INTERFACE=$(echo "$IFACE_LINE" | awk '{print $2}' | tr -d ':')
            IPV6_ADDR=$(ip -6 addr show "$IPV6_INTERFACE" scope global 2>/dev/null | grep "inet6" | grep -v "fe80" | head -1 | awk '{print $2}' | cut -d'/' -f1)
            
            if [ -n "$IPV6_ADDR" ]; then
                IPV6_PREFIX=$(echo "$IPV6_ADDR" | cut -d':' -f1-4)
            fi
        fi
    fi
    
    # 方法2: 尝试常见接口名
    if [ -z "$IPV6_INTERFACE" ]; then
        for iface in eth0 ens3 ens5 enp0s3 venet0:0 venet0; do
            if ip -6 addr show "$iface" 2>/dev/null | grep -q "inet6.*scope global"; then
                IPV6_INTERFACE="$iface"
                IPV6_ADDR=$(ip -6 addr show "$iface" | grep "inet6.*scope global" | awk '{print $2}' | cut -d'/' -f1 | head -1)
                IPV6_PREFIX=$(echo "$IPV6_ADDR" | cut -d':' -f1-4)
                break
            fi
        done
    fi
    
    if [ -n "$IPV6_INTERFACE" ] && [ -n "$IPV6_PREFIX" ]; then
        print_success "检测到 IPv6: $IPV6_PREFIX::/64"
        print_info "接口: $IPV6_INTERFACE"
        
        read -p "启用 IPv6 轮换? [Y/n] " use_ipv6
        if [[ ! $use_ipv6 =~ ^[Nn]$ ]]; then
            USE_IPV6=true
        fi
    else
        print_warning "无法自动检测 IPv6 配置"
        read -p "是否手动输入？ [y/N] " manual_ipv6
        if [[ $manual_ipv6 =~ ^[Yy]$ ]]; then
            read -p "请输入 IPv6 前缀 (如 2602:294:1:bf21): " IPV6_PREFIX
            read -p "请输入网卡接口 (如 eth0): " IPV6_INTERFACE
            if [ -n "$IPV6_PREFIX" ] && [ -n "$IPV6_INTERFACE" ]; then
                USE_IPV6=true
            fi
        fi
    fi
fi

if ! $USE_IPV6; then
    print_warning "IPv6 未启用，将只使用 IPv4"
fi

echo ""

# 端口
read -p "代理端口数量 [1000]: " PORT_COUNT
PORT_COUNT=${PORT_COUNT:-1000}

read -p "起始端口 [20000]: " START_PORT
START_PORT=${START_PORT:-20000}

END_PORT=$((START_PORT + PORT_COUNT - 1))

if [ "$END_PORT" -gt 65535 ]; then
    print_error "端口超限: $START_PORT-$END_PORT"
    exit 1
fi

# 监控
read -p "监控端口 [10001]: " METRICS_PORT
METRICS_PORT=${METRICS_PORT:-10001}

# 认证
read -p "用户名 [proxy]: " USERNAME
USERNAME=${USERNAME:-proxy}
read -sp "密码 [回车生成]: " PASSWORD
echo ""
[ -z "$PASSWORD" ] && PASSWORD=$(openssl rand -hex 8) && print_info "密码: $PASSWORD"

# 确认
echo ""
echo "========================================="
echo "配置摘要"
echo "========================================="
echo "IP: $IPV4"
echo "端口: $START_PORT-$END_PORT ($PORT_COUNT个)"
echo "监控: $METRICS_PORT"
echo "用户: $USERNAME"
echo "密码: $PASSWORD"
if $USE_IPV6; then
    echo ""
    echo "IPv6: $IPV6_PREFIX::/64"
    echo "接口: $IPV6_INTERFACE"
    echo "策略: SNAT 方案，每端口固定 IPv6"
    echo "清理: 每 10 分钟自动清理连接跟踪"
fi
echo "========================================="
echo ""

read -p "确认安装? [Y/n] " confirm
[[ $confirm =~ ^[Nn]$ ]] && exit 0

# ==================== 依赖 ====================
print_info "安装依赖..."

if command -v apt-get &> /dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq 2>&1 | grep -E "^(Hit|Get|Fetched)" || true
    apt-get install -y build-essential curl wget iptables 2>&1 | grep -E "^(Setting|Processing|Unpacking)" || echo "  - 安装完成"
elif command -v yum &> /dev/null; then
    yum install -y gcc-c++ curl wget iptables 2>&1 | grep -E "^(Installing|Updating)" || echo "  - 安装完成"
fi

print_success "依赖完成"

# ==================== 系统优化 ====================
print_info "系统优化..."

cat > /etc/security/limits.d/ipv6-proxy.conf << 'EOF'
* soft nofile 10000000
* hard nofile 10000000
root soft nofile 10000000
root hard nofile 10000000
EOF

cat > /etc/sysctl.d/ipv6-proxy.conf << EOF
fs.file-max = 10000000
fs.nr_open = 10000000
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_max_tw_buckets = 5000000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.netfilter.nf_conntrack_max = 10000000
net.nf_conntrack_max = 10000000
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.${IPV6_INTERFACE}.forwarding = 1
net.ipv6.ip_nonlocal_bind = 1
vm.overcommit_memory = 1
EOF

sysctl -p /etc/sysctl.d/ipv6-proxy.conf >/dev/null 2>&1 || true
print_success "系统优化完成"

# ==================== Go ====================
print_info "检查 Go..."

export PATH=$PATH:/usr/local/go/bin
if ! command -v go &> /dev/null; then
    print_info "安装 Go..."
    cd /tmp
    wget -q --show-progress https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    print_success "Go 安装完成"
else
    print_success "Go 已安装: $(go version | awk '{print $3}')"
fi

# ==================== IPv6 SNAT 配置 ====================
if $USE_IPV6; then
    print_info "配置 IPv6 SNAT 规则..."
    
    # 清理旧规则
    ip6tables -t nat -F 2>/dev/null || true
    
    # 生成 IPv6 地址池文件
    mkdir -p /etc/ipv6-proxy
    cat > /etc/ipv6-proxy/ipv6-pool.txt << POOL_EOF
# IPv6 地址池 (端口:IPv6)
# 格式: PORT=IPv6_ADDRESS
POOL_EOF
    
    print_info "生成 IPv6 地址池..."
    for ((i=0; i<PORT_COUNT; i++)); do
        PORT=$((START_PORT + i))
        # 为每个端口生成一个固定的 IPv6
        IPV6="${IPV6_PREFIX}:$(printf '%x' $((i / 65536))):$(printf '%x' $((i % 65536))):$(printf '%x' $RANDOM):$(printf '%x' $RANDOM)"
        echo "$PORT=$IPV6" >> /etc/ipv6-proxy/ipv6-pool.txt
    done
    
    print_success "IPv6 地址池生成完成 ($PORT_COUNT 个)"
    
    # 创建 SNAT 规则脚本
    cat > /etc/ipv6-proxy/setup-snat.sh << 'SNAT_SCRIPT'
#!/bin/bash

# 清理旧规则
ip6tables -t nat -F 2>/dev/null || true
ip6tables -t nat -X 2>/dev/null || true

# 读取配置
IPV6_INTERFACE=$(grep "^IPV6_INTERFACE=" /etc/ipv6-proxy/config.txt | cut -d'=' -f2)

# 应用 SNAT 规则
while IFS='=' read -r PORT IPV6; do
    [[ "$PORT" =~ ^#.*$ || -z "$PORT" ]] && continue
    ip6tables -t nat -A POSTROUTING -p tcp -o "$IPV6_INTERFACE" -m mark --mark "$PORT" -j SNAT --to-source "$IPV6"
done < /etc/ipv6-proxy/ipv6-pool.txt

echo "✓ SNAT 规则已应用"
SNAT_SCRIPT
    
    chmod +x /etc/ipv6-proxy/setup-snat.sh
    
    print_success "IPv6 SNAT 配置完成"
fi

# ==================== 定时清理服务 ====================
if $USE_IPV6; then
    print_info "配置定时清理服务..."
    
    cat > /etc/ipv6-proxy/cleanup.sh << 'CLEANUP_SCRIPT'
#!/bin/bash

LOG_FILE="/var/log/ipv6-proxy-cleanup.log"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# 清理 conntrack 表中的旧连接
cleanup_conntrack() {
    BEFORE=$(conntrack -C 2>/dev/null | awk '{print $1}' || echo 0)
    
    # 清理 TIME_WAIT 状态的连接
    conntrack -D -p tcp --state TIME_WAIT 2>/dev/null || true
    
    # 清理超过 5 分钟的 ESTABLISHED 连接
    conntrack -D -p tcp --state ESTABLISHED --timeout 300 2>/dev/null || true
    
    AFTER=$(conntrack -C 2>/dev/null | awk '{print $1}' || echo 0)
    CLEANED=$((BEFORE - AFTER))
    
    log_msg "Conntrack 清理: $BEFORE → $AFTER (清理 $CLEANED)"
}

# 清理无用的 IPv6 邻居缓存
cleanup_ipv6_neigh() {
    IPV6_INTERFACE=$(grep "^IPV6_INTERFACE=" /etc/ipv6-proxy/config.txt | cut -d'=' -f2)
    
    if [ -n "$IPV6_INTERFACE" ]; then
        BEFORE=$(ip -6 neigh show dev "$IPV6_INTERFACE" | wc -l)
        ip -6 neigh flush dev "$IPV6_INTERFACE" 2>/dev/null || true
        log_msg "IPv6 邻居缓存清理: $BEFORE 条"
    fi
}

# 主清理流程
log_msg "========== 开始定时清理 =========="
cleanup_conntrack
cleanup_ipv6_neigh
log_msg "========== 清理完成 =========="
log_msg ""
CLEANUP_SCRIPT
    
    chmod +x /etc/ipv6-proxy/cleanup.sh
    
    # 创建定时清理服务
    cat > /etc/systemd/system/ipv6-cleanup.service << 'CLEANUP_SERVICE'
[Unit]
Description=IPv6 Proxy Cleanup Service

[Service]
Type=oneshot
ExecStart=/etc/ipv6-proxy/cleanup.sh
CLEANUP_SERVICE
    
    # 创建定时器
    cat > /etc/systemd/system/ipv6-cleanup.timer << 'CLEANUP_TIMER'
[Unit]
Description=IPv6 Proxy Cleanup Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
CLEANUP_TIMER
    
    systemctl daemon-reload
    systemctl enable ipv6-cleanup.timer
    systemctl start ipv6-cleanup.timer
    
    print_success "定时清理服务已配置 (每 10 分钟)"
fi

# ==================== 创建代理程序 ====================
print_info "创建代理程序..."

rm -rf /opt/ipv6-proxy
mkdir -p /opt/ipv6-proxy /etc/ipv6-proxy
cd /opt/ipv6-proxy

cat > /etc/ipv6-proxy/config.txt << CONFIG
START_PORT=$START_PORT
PORT_COUNT=$PORT_COUNT
METRICS_PORT=$METRICS_PORT
USERNAME=$USERNAME
PASSWORD=$PASSWORD
IPV6_ENABLED=$USE_IPV6
IPV6_PREFIX=$IPV6_PREFIX
IPV6_INTERFACE=$IPV6_INTERFACE
CONFIG

cat > main.go << 'GOCODE'
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	cfg          Config
	ipv6Pool     map[int]string // port -> ipv6
	activeConns  int64
	totalConns   int64
	successConns int64
	failedConns  int64
	bytesIn      int64
	bytesOut     int64
	portSuccess  int64
	portFailed   int64
	bufferPool   = sync.Pool{New: func() interface{} { return make([]byte, 8192) }}
)

type Config struct {
	StartPort     string
	PortCount     string
	MetricsPort   string
	Username      string
	Password      string
	IPv6Prefix    string
	IPv6Interface string
	IPv6Enabled   bool
}

func loadConfig() error {
	data, err := os.ReadFile("/etc/ipv6-proxy/config.txt")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch key {
			case "START_PORT":
				cfg.StartPort = val
			case "PORT_COUNT":
				cfg.PortCount = val
			case "METRICS_PORT":
				cfg.MetricsPort = val
			case "USERNAME":
				cfg.Username = val
			case "PASSWORD":
				cfg.Password = val
			case "IPV6_ENABLED":
				cfg.IPv6Enabled = val == "true"
			case "IPV6_PREFIX":
				cfg.IPv6Prefix = val
			case "IPV6_INTERFACE":
				cfg.IPv6Interface = val
			}
		}
	}
	return nil
}

func loadIPv6Pool() error {
	ipv6Pool = make(map[int]string)
	
	if !cfg.IPv6Enabled {
		return nil
	}
	
	data, err := os.ReadFile("/etc/ipv6-proxy/ipv6-pool.txt")
	if err != nil {
		return err
	}
	
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			port, _ := strconv.Atoi(parts[0])
			ipv6 := parts[1]
			ipv6Pool[port] = ipv6
		}
	}
	
	log.Printf("加载 IPv6 地址池: %d 个", len(ipv6Pool))
	return nil
}

func checkAuth(h string) bool {
	exp := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
	for _, l := range strings.Split(h, "\r\n") {
		if strings.HasPrefix(strings.ToLower(l), "proxy-authorization: basic ") {
			return strings.TrimSpace(l[27:]) == exp
		}
	}
	return false
}

func handleSOCKS5(c net.Conn, localPort int) error {
	buf := make([]byte, 512)
	
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	// 1. 握手
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS version")
	}
	
	nmethods := int(buf[1])
	if _, err := io.ReadFull(c, buf[:nmethods]); err != nil {
		return err
	}
	
	// 2. 要求认证
	c.Write([]byte{5, 2})
	
	// 3. 认证
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 1 {
		return fmt.Errorf("invalid auth version")
	}
	
	ulen := int(buf[1])
	if _, err := io.ReadFull(c, buf[:ulen]); err != nil {
		return err
	}
	user := string(buf[:ulen])
	
	if _, err := io.ReadFull(c, buf[:1]); err != nil {
		return err
	}
	plen := int(buf[0])
	if _, err := io.ReadFull(c, buf[:plen]); err != nil {
		return err
	}
	pass := string(buf[:plen])
	
	if user != cfg.Username || pass != cfg.Password {
		c.Write([]byte{1, 1})
		return fmt.Errorf("auth failed")
	}
	c.Write([]byte{1, 0})
	
	// 4. 连接请求
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return err
	}
	if buf[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("only CONNECT supported")
	}
	
	var host string
	var port uint16
	
	if buf[3] == 1 { // IPv4
		if _, err := io.ReadFull(c, buf[:6]); err != nil {
			return err
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		port = binary.BigEndian.Uint16(buf[4:6])
	} else if buf[3] == 3 { // Domain
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return err
		}
		dlen := int(buf[0])
		if _, err := io.ReadFull(c, buf[:dlen+2]); err != nil {
			return err
		}
		host = string(buf[:dlen])
		port = binary.BigEndian.Uint16(buf[dlen : dlen+2])
	} else if buf[3] == 4 { // IPv6
		if _, err := io.ReadFull(c, buf[:18]); err != nil {
			return err
		}
		host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
			binary.BigEndian.Uint16(buf[0:2]),
			binary.BigEndian.Uint16(buf[2:4]),
			binary.BigEndian.Uint16(buf[4:6]),
			binary.BigEndian.Uint16(buf[6:8]),
			binary.BigEndian.Uint16(buf[8:10]),
			binary.BigEndian.Uint16(buf[10:12]),
			binary.BigEndian.Uint16(buf[12:14]),
			binary.BigEndian.Uint16(buf[14:16]))
		port = binary.BigEndian.Uint16(buf[16:18])
	} else {
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("unsupported address type")
	}
	
	return connectAndForward(c, host, port, localPort, true)
}

func handleHTTP(c net.Conn, fb byte, localPort int) error {
	r := bufio.NewReader(io.MultiReader(strings.NewReader(string(fb)), c))
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return fmt.Errorf("invalid request")
	}
	
	var h strings.Builder
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			break
		}
		h.WriteString(l)
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	
	if !checkAuth(h.String()) {
		c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
		return fmt.Errorf("auth failed")
	}
	
	if parts[0] != "CONNECT" {
		c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return fmt.Errorf("method not allowed")
	}
	
	hp := strings.Split(parts[1], ":")
	if len(hp) != 2 {
		return fmt.Errorf("invalid host:port")
	}
	
	port, _ := strconv.Atoi(hp[1])
	return connectAndForward(c, hp[0], uint16(port), localPort, false)
}

func connectAndForward(c net.Conn, host string, port uint16, localPort int, socks bool) error {
	var d net.Dialer
	d.Timeout = 30 * time.Second
	
	// 使用 SO_MARK 标记连接，用于 iptables SNAT
	if cfg.IPv6Enabled {
		d.Control = func(network, address string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, localPort)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		}
	}
	
	remote, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		atomic.AddInt64(&failedConns, 1)
		if socks {
			c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		return err
	}
	
	defer remote.Close()
	
	if tcp, ok := remote.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	
	atomic.AddInt64(&successConns, 1)
	
	if socks {
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	} else {
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}
	
	deadline := time.Now().Add(5 * time.Minute)
	c.SetDeadline(deadline)
	remote.SetDeadline(deadline)
	
	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(remote, c, "up", &wg)
	go transfer(c, remote, "down", &wg)
	wg.Wait()
	
	return nil
}

func transfer(dst io.Writer, src io.Reader, dir string, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if dir == "up" {
				atomic.AddInt64(&bytesOut, int64(n))
			} else {
				atomic.AddInt64(&bytesIn, int64(n))
			}
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func handleConn(c net.Conn, port int) {
	atomic.AddInt64(&activeConns, 1)
	atomic.AddInt64(&totalConns, 1)
	defer func() {
		c.Close()
		atomic.AddInt64(&activeConns, -1)
	}()
	
	c.SetDeadline(time.Now().Add(30 * time.Second))
	
	fb := make([]byte, 1)
	if _, err := c.Read(fb); err != nil {
		return
	}
	
	c.SetDeadline(time.Time{})
	
	var err error
	if fb[0] == 0x05 {
		err = handleSOCKS5(c, port)
	} else {
		err = handleHTTP(c, fb[0], port)
	}
	
	if err != nil {
		atomic.AddInt64(&failedConns, 1)
	}
}

func startProxyServer(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		atomic.AddInt64(&portFailed, 1)
		return err
	}
	atomic.AddInt64(&portSuccess, 1)
	
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go handleConn(conn, port)
		}
	}()
	return nil
}

func statsRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		log.Printf("[统计] 活跃:%d 总计:%d 成功:%d 失败:%d 入站:%.2fGB 出站:%.2fGB",
			atomic.LoadInt64(&activeConns),
			atomic.LoadInt64(&totalConns),
			atomic.LoadInt64(&successConns),
			atomic.LoadInt64(&failedConns),
			float64(atomic.LoadInt64(&bytesIn))/1e9,
			float64(atomic.LoadInt64(&bytesOut))/1e9)
	}
}

func metricsServer() {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proxy_ports_total %s\n", cfg.PortCount)
		fmt.Fprintf(w, "proxy_ports_success %d\n", atomic.LoadInt64(&portSuccess))
		fmt.Fprintf(w, "proxy_ports_failed %d\n", atomic.LoadInt64(&portFailed))
		fmt.Fprintf(w, "proxy_active_conns %d\n", atomic.LoadInt64(&activeConns))
		fmt.Fprintf(w, "proxy_total_conns %d\n", atomic.LoadInt64(&totalConns))
		fmt.Fprintf(w, "proxy_success_conns %d\n", atomic.LoadInt64(&successConns))
		fmt.Fprintf(w, "proxy_failed_conns %d\n", atomic.LoadInt64(&failedConns))
		fmt.Fprintf(w, "proxy_bytes_in %d\n", atomic.LoadInt64(&bytesIn))
		fmt.Fprintf(w, "proxy_bytes_out %d\n", atomic.LoadInt64(&bytesOut))
		fmt.Fprintf(w, "proxy_ipv6_pool_size %d\n", len(ipv6Pool))
	})
	
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK\n")
	})
	
	http.ListenAndServe(":"+cfg.MetricsPort, mux)
}

func setupSNAT() error {
	if !cfg.IPv6Enabled {
		return nil
	}
	
	log.Printf("配置 SNAT 规则...")
	
	cmd := exec.Command("/etc/ipv6-proxy/setup-snat.sh")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SNAT 配置失败: %v\n%s", err, output)
	}
	
	log.Printf("%s", strings.TrimSpace(string(output)))
	return nil
}

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	if err := loadIPv6Pool(); err != nil {
		log.Printf("警告: 加载 IPv6 池失败: %v", err)
	}
	
	if err := setupSNAT(); err != nil {
		log.Printf("警告: SNAT 配置失败: %v", err)
	}
	
	startPort, _ := strconv.Atoi(cfg.StartPort)
	portCount, _ := strconv.Atoi(cfg.PortCount)
	endPort := startPort + portCount - 1
	
	log.Printf("IPv6 Rotating Proxy (SNAT) | 端口: %d-%d (%d个) | IPv6: %v", startPort, endPort, portCount, cfg.IPv6Enabled)
	if cfg.IPv6Enabled {
		log.Printf("SNAT 方案: 每端口固定 IPv6，基于 SO_MARK 标记")
	}
	
	go statsRoutine()
	go metricsServer()
	
	log.Printf("正在启动 %d 个代理端口...", portCount)
	for i := 0; i < portCount; i++ {
		go startProxyServer(startPort + i)
		if (i+1)%100 == 0 || i == portCount-1 {
			log.Printf("进度: %d/%d (%.1f%%)", i+1, portCount, float64(i+1)/float64(portCount)*100)
		}
	}
	
	time.Sleep(2 * time.Second)
	log.Printf("启动完成! 成功: %d | 失败: %d", atomic.LoadInt64(&portSuccess), atomic.LoadInt64(&portFailed))
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	
	log.Printf("服务运行中, 按 Ctrl+C 关闭...")
	<-sigChan
	log.Printf("收到关闭信号, 优雅退出中...")
}
GOCODE

print_info "编译代理程序..."
go mod init ipv6-proxy >/dev/null 2>&1 || true
go build -ldflags="-s -w" -o ipv6-proxy main.go

if [ -f "ipv6-proxy" ]; then
    print_success "编译完成"
else
    print_error "编译失败"
    exit 1
fi

# ==================== 创建服务 ====================
cat > /etc/systemd/system/ipv6-proxy.service << 'SERVICE_EOF'
[Unit]
Description=IPv6 Rotating Proxy (SNAT)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ipv6-proxy
ExecStartPre=/etc/ipv6-proxy/setup-snat.sh
ExecStart=/opt/ipv6-proxy/ipv6-proxy
Restart=always
RestartSec=5
LimitNOFILE=infinity
LimitNPROC=infinity

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable ipv6-proxy
systemctl start ipv6-proxy

sleep 3

# ==================== 验证 ====================
if systemctl is-active --quiet ipv6-proxy; then
    print_success "代理服务启动成功"
else
    print_error "代理服务启动失败"
    journalctl -u ipv6-proxy -n 20 --no-pager
    exit 1
fi

if $USE_IPV6; then
    echo ""
    print_info "验证 IPv6 SNAT..."
    
    # 检查 iptables 规则
    RULE_COUNT=$(ip6tables -t nat -L POSTROUTING -n | grep -c "SNAT" || echo 0)
    if [ "$RULE_COUNT" -gt 0 ]; then
        print_success "SNAT 规则已配置 ($RULE_COUNT 条)"
    else
        print_warning "未检测到 SNAT 规则"
    fi
    
    # 检查定时器
    if systemctl is-active --quiet ipv6-cleanup.timer; then
        print_success "定时清理服务运行中"
    fi
fi

# ==================== 完成 ====================
echo ""
echo "========================================="
print_success "安装完成!"
echo "========================================="
echo ""
echo "服务器: $IPV4"
echo "端口: $START_PORT-$END_PORT ($PORT_COUNT个)"
echo "用户: $USERNAME"
echo "密码: $PASSWORD"
echo ""
if $USE_IPV6; then
    echo "IPv6: $IPV6_PREFIX::/64"
    echo "方案: SNAT (每端口固定 IPv6)"
    echo "清理: 每 10 分钟自动清理"
    echo ""
fi
echo "测试命令:"
echo ""
echo "# HTTP:"
echo "curl -x http://$USERNAME:$PASSWORD@$IPV4:$START_PORT http://ip.sb"
echo ""
echo "# SOCKS5:"
echo "curl -x socks5://$USERNAME:$PASSWORD@$IPV4:$START_PORT http://ip.sb"
echo ""
if $USE_IPV6; then
    echo "# IPv6 (不同端口=不同IPv6):"
    echo "curl -x http://$USERNAME:$PASSWORD@$IPV4:$START_PORT http://ipv6.ip.sb"
    echo "curl -x http://$USERNAME:$PASSWORD@$IPV4:$((START_PORT+1)) http://ipv6.ip.sb"
    echo ""
fi
echo "# 监控:"
echo "curl http://localhost:$METRICS_PORT/metrics"
echo ""
echo "# 日志:"
echo "journalctl -u ipv6-proxy -f"
echo ""
echo "# 清理日志:"
echo "tail -f /var/log/ipv6-proxy-cleanup.log"
echo ""
echo "# SNAT 规则:"
echo "ip6tables -t nat -L POSTROUTING -n -v | head -20"
echo ""
echo "# 清理状态:"
echo "systemctl status ipv6-cleanup.timer"
echo "========================================="
