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
echo "  IPv6 Rotating Proxy - 极简高性能版"
echo "  ✅ 每IP限制5并发"
echo "  ✅ 2^64个IPv6池"
echo "  ✅ 纯随机负载均衡"
echo "  ✅ ndppd自动NDP"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    print_error "请使用 root 权限运行"
    exit 1
fi

# ==================== 清理 ====================
print_info "清理现有服务..."

for service in go-proxy ipv6-proxy ipv6-proxy-multi dynamic-proxy python-proxy ndppd; do
    systemctl stop $service 2>/dev/null || true
    systemctl disable $service 2>/dev/null || true
    rm -f /etc/systemd/system/$service.service
done

systemctl daemon-reload
pkill -9 -f "ipv6-proxy" 2>/dev/null || true
pkill -9 -f "ndppd" 2>/dev/null || true

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
        # 直接从接口定义行获取接口名
        IFACE_LINE=$(ip -6 addr show scope global 2>/dev/null | grep -E "^[0-9]+:" | head -1)
        if [ -n "$IFACE_LINE" ]; then
            # 提取接口名：格式是 "2: eth0: <FLAGS>"
            IPV6_INTERFACE=$(echo "$IFACE_LINE" | awk '{print $2}' | tr -d ':')
            
            # 获取该接口的全局IPv6地址（排除fe80）
            IPV6_ADDR=$(ip -6 addr show "$IPV6_INTERFACE" scope global 2>/dev/null | grep "inet6" | grep -v "fe80" | head -1 | awk '{print $2}' | cut -d'/' -f1)
            
            if [ -n "$IPV6_ADDR" ]; then
                IPV6_PREFIX=$(echo "$IPV6_ADDR" | cut -d':' -f1-4)
            fi
        fi
    fi
    
    # 方法2: 使用 ifconfig（备用）
    if [ -z "$IPV6_INTERFACE" ] && command -v ifconfig &>/dev/null; then
        # 查找有全局IPv6的接口
        for iface in $(ifconfig -a | grep -oP '^[a-z0-9]+(?=:)'); do
            IPV6_TEST=$(ifconfig "$iface" 2>/dev/null | grep "inet6" | grep -v "fe80" | grep -v "::1" | head -1)
            if [ -n "$IPV6_TEST" ]; then
                IPV6_INTERFACE="$iface"
                IPV6_ADDR=$(echo "$IPV6_TEST" | awk '{print $2}' | cut -d'/' -f1)
                IPV6_PREFIX=$(echo "$IPV6_ADDR" | cut -d':' -f1-4)
                break
            fi
        done
    fi
    
    # 方法3: 尝试常见接口名
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
    echo "策略: 每IP限制5并发，自动负载均衡"
    EXPECTED_IPV6=$(( 200000 / 5 ))
    echo "预计: 20万并发需要约 ${EXPECTED_IPV6} 个活跃IPv6"
fi
echo "========================================="
echo ""

read -p "确认安装? [Y/n] " confirm
[[ $confirm =~ ^[Nn]$ ]] && exit 0

# ==================== 依赖 ====================
print_info "安装依赖..."

if command -v apt-get &> /dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    print_info "更新软件包列表..."
    apt-get update -qq 2>&1 | grep -E "^(Hit|Get|Fetched)" || true
    
    print_info "安装编译工具..."
    apt-get install -y build-essential 2>&1 | grep -E "^(Setting|Processing|Unpacking)" || echo "  - build-essential"
    
    print_info "安装 Boost 库..."
    apt-get install -y libboost-all-dev 2>&1 | grep -E "^(Setting|Processing|Unpacking)" || echo "  - libboost-all-dev"
    
    print_info "安装其他依赖..."
    apt-get install -y g++ cmake git curl wget 2>&1 | grep -E "^(Setting|Processing|Unpacking)" || echo "  - g++ cmake git curl wget"
    
elif command -v yum &> /dev/null; then
    print_info "安装编译工具..."
    yum install -y gcc-c++ boost-devel cmake git curl wget 2>&1 | grep -E "^(Installing|Updating)" || echo "  - 依赖包安装中..."
fi

print_success "依赖完成"

# ==================== ndppd ====================
if $USE_IPV6; then
    print_info "安装 ndppd..."
    
    cd /tmp
    rm -rf ndppd
    
    if ! git clone -q https://github.com/DanielAdolfsson/ndppd.git 2>/dev/null; then
        wget -q https://github.com/DanielAdolfsson/ndppd/archive/refs/heads/master.zip -O ndppd.zip
        unzip -q ndppd.zip
        mv ndppd-master ndppd
    fi
    
    cd ndppd
    print_info "编译 ndppd (可能需要1-2分钟)..."
    if make -j$(nproc) 2>&1 | grep -E "^\[|%|Building|Compiling" || make -j$(nproc) >/dev/null 2>&1; then
        print_success "编译成功"
    else
        print_error "编译失败"
        exit 1
    fi
    
    if [ -f "ndppd" ]; then
        cp ndppd /usr/local/sbin/
        chmod +x /usr/local/sbin/ndppd
        print_success "ndppd 编译完成"
    else
        print_error "ndppd 编译失败"
        exit 1
    fi
    
    mkdir -p /etc/ndppd
    cat > /etc/ndppd/ndppd.conf << NDPPD_EOF
route-ttl 30000

proxy ${IPV6_INTERFACE} {
    router no
    timeout 500
    ttl 30000
    
    rule ${IPV6_PREFIX}::/64 {
        auto
    }
}
NDPPD_EOF
    
    cat > /etc/systemd/system/ndppd.service << 'NDPPD_SERVICE'
[Unit]
Description=NDP Proxy Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/ndppd -c /etc/ndppd/ndppd.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
NDPPD_SERVICE
    
    systemctl daemon-reload
    systemctl enable ndppd >/dev/null 2>&1
    systemctl start ndppd
    
    sleep 2
    
    if systemctl is-active --quiet ndppd; then
        print_success "ndppd 启动成功"
    else
        print_warning "ndppd 启动失败（将由代理程序自动修复）"
    fi
fi

# ==================== IPv6 路由 ====================
if $USE_IPV6; then
    print_info "配置 IPv6 路由..."
    
    ip -6 route add local ${IPV6_PREFIX}::/64 dev lo 2>/dev/null || true
    sysctl -w net.ipv6.conf.${IPV6_INTERFACE}.proxy_ndp=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
    sysctl -w net.ipv6.conf.${IPV6_INTERFACE}.accept_ra=0 >/dev/null 2>&1
    sysctl -w net.ipv6.ip_nonlocal_bind=1 >/dev/null 2>&1
    
    cat > /etc/ipv6-proxy-route.sh << ROUTE_SCRIPT
#!/bin/bash
ip -6 route add local ${IPV6_PREFIX}::/64 dev lo 2>/dev/null || true
sysctl -w net.ipv6.conf.${IPV6_INTERFACE}.proxy_ndp=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.${IPV6_INTERFACE}.accept_ra=0 >/dev/null 2>&1
sysctl -w net.ipv6.ip_nonlocal_bind=1 >/dev/null 2>&1
ROUTE_SCRIPT
    chmod +x /etc/ipv6-proxy-route.sh
    
    print_success "IPv6 路由配置完成"
fi

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
net.ipv6.conf.${IPV6_INTERFACE}.proxy_ndp = 1
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
	"math/rand"
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
	ipv6Manager  *IPv6Manager
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

type IPv6Manager struct {
	activeConns sync.Map // map[string]*int64
	maxPerIP    int64
	prefix      string
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

func NewIPv6Manager(prefix string) *IPv6Manager {
	return &IPv6Manager{
		maxPerIP: 5,
		prefix:   prefix,
	}
}

func (m *IPv6Manager) randomIPv6() string {
	if m.prefix == "" {
		return ""
	}
	return fmt.Sprintf("%s:%x:%x:%x:%x",
		m.prefix,
		rand.Int31n(0x10000),
		rand.Int31n(0x10000),
		rand.Int31n(0x10000),
		rand.Int31n(0x10000))
}

func (m *IPv6Manager) GetAvailableIPv6() string {
	if !cfg.IPv6Enabled {
		return ""
	}
	
	maxAttempts := 200
	for i := 0; i < maxAttempts; i++ {
		ipv6 := m.randomIPv6()
		
		val, _ := m.activeConns.LoadOrStore(ipv6, new(int64))
		counter := val.(*int64)
		current := atomic.LoadInt64(counter)
		
		if current < m.maxPerIP {
			atomic.AddInt64(counter, 1)
			return ipv6
		}
	}
	
	ipv6 := m.randomIPv6()
	val, _ := m.activeConns.LoadOrStore(ipv6, new(int64))
	atomic.AddInt64(val.(*int64), 1)
	return ipv6
}

func (m *IPv6Manager) ReleaseIPv6(ipv6 string) {
	if ipv6 == "" {
		return
	}
	if val, ok := m.activeConns.Load(ipv6); ok {
		counter := val.(*int64)
		newCount := atomic.AddInt64(counter, -1)
		if newCount <= 0 {
			m.activeConns.Delete(ipv6)
		}
	}
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

func handleSOCKS5(c net.Conn, ipv6 string) error {
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
	
	return connectAndForward(c, host, port, ipv6, true)
}

func handleHTTP(c net.Conn, fb byte, ipv6 string) error {
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
	return connectAndForward(c, hp[0], uint16(port), ipv6, false)
}

func connectAndForward(c net.Conn, host string, port uint16, ipv6 string, socks bool) error {
	var d net.Dialer
	d.Timeout = 30 * time.Second
	
	if ipv6 != "" {
		if addr, err := net.ResolveIPAddr("ip6", ipv6); err == nil {
			d.LocalAddr = &net.TCPAddr{IP: addr.IP}
		}
	}
	
	d.Control = func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
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

func handleConn(c net.Conn) {
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
	
	ipv6 := ipv6Manager.GetAvailableIPv6()
	defer ipv6Manager.ReleaseIPv6(ipv6)
	
	var err error
	if fb[0] == 0x05 {
		err = handleSOCKS5(c, ipv6)
	} else {
		err = handleHTTP(c, fb[0], ipv6)
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
			go handleConn(conn)
		}
	}()
	return nil
}

func statsRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		activeIPCount := 0
		ipv6Manager.activeConns.Range(func(key, value interface{}) bool {
			activeIPCount++
			return true
		})
		
		log.Printf("[统计] 活跃:%d 总计:%d 成功:%d 失败:%d 活跃IPv6:%d 入站:%.2fGB 出站:%.2fGB",
			atomic.LoadInt64(&activeConns),
			atomic.LoadInt64(&totalConns),
			atomic.LoadInt64(&successConns),
			atomic.LoadInt64(&failedConns),
			activeIPCount,
			float64(atomic.LoadInt64(&bytesIn))/1e9,
			float64(atomic.LoadInt64(&bytesOut))/1e9)
	}
}

func metricsServer() {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		activeIPCount := 0
		ipv6Manager.activeConns.Range(func(key, value interface{}) bool {
			activeIPCount++
			return true
		})
		
		fmt.Fprintf(w, "proxy_ports_total %s\n", cfg.PortCount)
		fmt.Fprintf(w, "proxy_ports_success %d\n", atomic.LoadInt64(&portSuccess))
		fmt.Fprintf(w, "proxy_ports_failed %d\n", atomic.LoadInt64(&portFailed))
		fmt.Fprintf(w, "proxy_active_conns %d\n", atomic.LoadInt64(&activeConns))
		fmt.Fprintf(w, "proxy_total_conns %d\n", atomic.LoadInt64(&totalConns))
		fmt.Fprintf(w, "proxy_success_conns %d\n", atomic.LoadInt64(&successConns))
		fmt.Fprintf(w, "proxy_failed_conns %d\n", atomic.LoadInt64(&failedConns))
		fmt.Fprintf(w, "proxy_active_ipv6 %d\n", activeIPCount)
		fmt.Fprintf(w, "proxy_bytes_in %d\n", atomic.LoadInt64(&bytesIn))
		fmt.Fprintf(w, "proxy_bytes_out %d\n", atomic.LoadInt64(&bytesOut))
	})
	
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK\n")
	})
	
	http.ListenAndServe(":"+cfg.MetricsPort, mux)
}

func autoDetectIPv6Interface() (string, string, error) {
	// 方法1: 读取 /proc/net/if_inet6
	data, err := os.ReadFile("/proc/net/if_inet6")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				// 跳过本地和链路本地地址
				if strings.HasPrefix(fields[0], "00000000") || strings.HasPrefix(fields[0], "fe80") {
					continue
				}
				iface := fields[5]
				addr := fields[0]
				if len(addr) == 32 {
					prefix := fmt.Sprintf("%s:%s:%s:%s", addr[0:4], addr[4:8], addr[8:12], addr[12:16])
					return iface, prefix, nil
				}
			}
		}
	}
	
	// 方法2: 尝试常见接口
	commonIfaces := []string{"eth0", "ens3", "ens5", "enp0s3", "enp1s0", "venet0"}
	for _, iface := range commonIfaces {
		data, err := os.ReadFile("/proc/net/if_inet6")
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) >= 6 && fields[5] == iface {
					addr := fields[0]
					if !strings.HasPrefix(addr, "fe80") && !strings.HasPrefix(addr, "00000000") {
						if len(addr) == 32 {
							prefix := fmt.Sprintf("%s:%s:%s:%s", addr[0:4], addr[4:8], addr[8:12], addr[12:16])
							return iface, prefix, nil
						}
					}
				}
			}
		}
	}
	
	return "", "", fmt.Errorf("无法检测IPv6接口")
}

func fixNdppd(iface, prefix string) error {
	// 更新 ndppd 配置文件
	ndppdConf := fmt.Sprintf(`route-ttl 30000

proxy %s {
    router no
    timeout 500
    ttl 30000
    
    rule %s::/64 {
        auto
    }
}
`, iface, prefix)
	
	err := os.WriteFile("/etc/ndppd/ndppd.conf", []byte(ndppdConf), 0644)
	if err != nil {
		return fmt.Errorf("更新ndppd配置失败: %v", err)
	}
	
	log.Printf("✓ ndppd 配置已更新: 接口=%s 前缀=%s::/64", iface, prefix)
	
	// 重启 ndppd 服务
	cmd := exec.Command("systemctl", "restart", "ndppd")
	if err := cmd.Run(); err != nil {
		log.Printf("警告: 重启ndppd失败: %v", err)
		return err
	}
	
	time.Sleep(1 * time.Second)
	
	// 检查服务状态
	cmd = exec.Command("systemctl", "is-active", "ndppd")
	output, _ := cmd.Output()
	if strings.TrimSpace(string(output)) == "active" {
		log.Printf("✓ ndppd 服务已成功重启")
		return nil
	}
	
	log.Printf("警告: ndppd 可能未正常运行")
	return nil
}

func fixIPv6Config() error {
	if !cfg.IPv6Enabled {
		return nil
	}
	
	// 检查配置是否有效
	needFix := cfg.IPv6Interface == "" || cfg.IPv6Interface == "global" || cfg.IPv6Interface == "lo"
	
	if needFix {
		log.Printf("⚠ 检测到无效的接口配置: '%s'", cfg.IPv6Interface)
		log.Printf("→ 开始自动修复...")
		
		iface, prefix, err := autoDetectIPv6Interface()
		if err != nil {
			return fmt.Errorf("自动检测失败: %v", err)
		}
		
		log.Printf("✓ 检测到正确配置: 接口=%s 前缀=%s", iface, prefix)
		
		// 更新内存中的配置
		cfg.IPv6Interface = iface
		if cfg.IPv6Prefix == "" || cfg.IPv6Prefix != prefix {
			cfg.IPv6Prefix = prefix
		}
		
		// 保存到配置文件
		configLines := []string{
			"START_PORT=" + cfg.StartPort,
			"PORT_COUNT=" + cfg.PortCount,
			"METRICS_PORT=" + cfg.MetricsPort,
			"USERNAME=" + cfg.Username,
			"PASSWORD=" + cfg.Password,
			"IPV6_ENABLED=true",
			"IPV6_PREFIX=" + cfg.IPv6Prefix,
			"IPV6_INTERFACE=" + cfg.IPv6Interface,
		}
		
		err = os.WriteFile("/etc/ipv6-proxy/config.txt", []byte(strings.Join(configLines, "\n")), 0644)
		if err != nil {
			log.Printf("警告: 无法保存配置文件: %v", err)
		} else {
			log.Printf("✓ 配置文件已自动修复")
		}
		
		// 修复 ndppd
		if err := fixNdppd(iface, prefix); err != nil {
			log.Printf("警告: ndppd修复失败: %v", err)
		}
		
		// 更新路由脚本
		routeScript := fmt.Sprintf(`#!/bin/bash
ip -6 route add local %s::/64 dev lo 2>/dev/null || true
sysctl -w net.ipv6.conf.%s.proxy_ndp=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.%s.accept_ra=0 >/dev/null 2>&1
sysctl -w net.ipv6.ip_nonlocal_bind=1 >/dev/null 2>&1
`, prefix, iface, iface)
		
		if err := os.WriteFile("/etc/ipv6-proxy-route.sh", []byte(routeScript), 0755); err != nil {
			log.Printf("警告: 无法更新路由脚本: %v", err)
		} else {
			// 执行路由配置
			cmd := exec.Command("/etc/ipv6-proxy-route.sh")
			if err := cmd.Run(); err != nil {
				log.Printf("警告: 执行路由配置失败: %v", err)
			} else {
				log.Printf("✓ IPv6 路由已配置")
			}
		}
		
		log.Printf("✓ IPv6 配置自动修复完成!")
	}
	
	return nil
}

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	
	rand.Seed(time.Now().UnixNano())
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	// 自动修复 IPv6 配置
	if err := fixIPv6Config(); err != nil {
		log.Printf("警告: IPv6配置修复失败: %v", err)
	}
	
	ipv6Manager = NewIPv6Manager(cfg.IPv6Prefix)
	
	startPort, _ := strconv.Atoi(cfg.StartPort)
	portCount, _ := strconv.Atoi(cfg.PortCount)
	endPort := startPort + portCount - 1
	
	log.Printf("IPv6 Rotating Proxy | 端口: %d-%d (%d个) | IPv6: %v", startPort, endPort, portCount, cfg.IPv6Enabled)
	if cfg.IPv6Enabled {
		log.Printf("IPv6配置: 接口=%s 前缀=%s 每IP限制=5并发", cfg.IPv6Interface, cfg.IPv6Prefix)
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
Description=IPv6 Rotating Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ipv6-proxy
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
    print_info "验证 IPv6..."
    
    if ip -6 route show | grep -q "${IPV6_PREFIX}::/64"; then
        print_success "IPv6 路由已配置"
    fi
    
    TEST_IPV6="${IPV6_PREFIX}:$(printf '%x' $RANDOM):$(printf '%x' $RANDOM):$(printf '%x' $RANDOM):$(printf '%x' $RANDOM)"
    print_info "测试 IPv6: $TEST_IPV6"
    
    if timeout 3 ping6 -c 1 -I $TEST_IPV6 2001:4860:4860::8888 &>/dev/null; then
        print_success "IPv6 测试通过"
    else
        print_warning "IPv6 测试失败(可能需要重启)"
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
    echo "策略: 每IP限制5并发，纯随机负载均衡"
    echo "说明: 单IP低并发极少触发429，无需额外重试"
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
    echo "# IPv6 (多次运行查看不同IP):"
    echo "curl -x http://$USERNAME:$PASSWORD@$IPV4:$START_PORT http://ipv6.ip.sb"
    echo ""
fi
echo "# 监控:"
echo "curl http://localhost:$METRICS_PORT/metrics"
echo ""
echo "# 日志:"
echo "journalctl -u ipv6-proxy -f"
echo ""
echo "# 状态:"
echo "systemctl status ipv6-proxy"
echo "========================================="
