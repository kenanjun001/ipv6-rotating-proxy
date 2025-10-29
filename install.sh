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
echo "  IPv6 Rotating Proxy - 多端口版本 (修复版)"
echo "  支持 1-100000 个代理端口"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    print_error "请使用 root 权限运行"
    exit 1
fi

# ==================== 第一步:清理现有服务 ====================
print_info "第 1 步:清理现有代理服务..."
echo ""

for service in go-proxy ipv6-proxy ipv6-proxy-multi dynamic-proxy python-proxy; do
    if systemctl list-unit-files | grep -q "^$service.service"; then
        systemctl stop $service 2>/dev/null || true
        systemctl disable $service 2>/dev/null || true
        rm -f /etc/systemd/system/$service.service
        print_success "已清理服务: $service"
    fi
done

systemctl daemon-reload

pkill -9 -f "ipv6-proxy" 2>/dev/null && print_success "已终止: ipv6-proxy" || true
pkill -9 -f "proxy-server" 2>/dev/null && print_success "已终止: proxy-server" || true

sleep 2
print_success "服务清理完成"
echo ""

# ==================== 第二步:交互式配置 ====================
print_info "第 2 步:配置参数..."
echo ""

# IPv4
IPV4=$(curl -s -4 --max-time 3 ifconfig.me 2>/dev/null || echo "")
if [ -z "$IPV4" ]; then
    read -p "请输入服务器 IPv4: " IPV4
else
    print_success "检测到 IPv4: $IPV4"
    read -p "确认使用此IP? [Y/n] " confirm
    [[ $confirm =~ ^[Nn]$ ]] && read -p "请输入 IPv4: " IPV4
fi

# IPv6
if ping6 -c 1 -W 2 2001:4860:4860::8888 &>/dev/null; then
    IPV6_ADDR=$(ip -6 addr show scope global 2>/dev/null | grep inet6 | head -1 | awk '{print $2}' | cut -d'/' -f1)
    if [ -n "$IPV6_ADDR" ]; then
        IPV6_PREFIX=$(echo "$IPV6_ADDR" | cut -d':' -f1-4)
        print_success "检测到 IPv6: $IPV6_PREFIX::/64"
        read -p "启用 IPv6 随机轮换? [Y/n] " use_ipv6
        [[ $use_ipv6 =~ ^[Nn]$ ]] && USE_IPV6=false || USE_IPV6=true
    else
        USE_IPV6=false
    fi
else
    print_warning "IPv6 不可用"
    USE_IPV6=false
    IPV6_PREFIX=""
fi

echo ""
print_info "=== 代理端口配置 ==="

# 端口数量
read -p "创建多少个代理端口? [1000]: " PORT_COUNT
PORT_COUNT=${PORT_COUNT:-1000}

if ! [[ "$PORT_COUNT" =~ ^[0-9]+$ ]] || [ "$PORT_COUNT" -lt 1 ] || [ "$PORT_COUNT" -gt 100000 ]; then
    print_error "端口数量必须在 1-100000 之间"
    exit 1
fi

# 起始端口
read -p "起始端口号? [20000]: " START_PORT
START_PORT=${START_PORT:-20000}

if ! [[ "$START_PORT" =~ ^[0-9]+$ ]] || [ "$START_PORT" -lt 1024 ] || [ "$START_PORT" -gt 65535 ]; then
    print_error "起始端口必须在 1024-65535 之间"
    exit 1
fi

END_PORT=$((START_PORT + PORT_COUNT - 1))

if [ "$END_PORT" -gt 65535 ]; then
    print_error "端口范围超出限制: $START_PORT-$END_PORT (最大65535)"
    exit 1
fi

# 监控端口
read -p "监控端口 [10001]: " METRICS_PORT
METRICS_PORT=${METRICS_PORT:-10001}

# 认证
read -p "用户名 [proxy]: " USERNAME
USERNAME=${USERNAME:-proxy}
read -sp "密码 [回车自动生成]: " PASSWORD
echo ""
[ -z "$PASSWORD" ] && PASSWORD=$(openssl rand -hex 8) && print_info "生成密码: $PASSWORD"

# 确认配置
echo ""
echo "========================================="
echo "  配置摘要"
echo "========================================="
echo "服务器 IP: $IPV4"
echo "代理数量: $PORT_COUNT 个"
echo "端口范围: $START_PORT - $END_PORT"
echo "监控端口: $METRICS_PORT"
echo "用户名: $USERNAME"
echo "密码: $PASSWORD"
$USE_IPV6 && echo "IPv6轮换: 启用 ($IPV6_PREFIX::/64)" || echo "IPv6轮换: 禁用"
echo "========================================="
echo ""

read -p "确认安装? [Y/n] " confirm
[[ $confirm =~ ^[Nn]$ ]] && exit 0

# ==================== 第三步:系统优化 ====================
print_info "第 3 步:优化系统参数..."

cat > /etc/security/limits.d/ipv6-proxy.conf << EOF
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
root soft nofile 1048576
root hard nofile 1048576
root soft nproc 1048576
root hard nproc 1048576
EOF

cat > /etc/sysctl.d/ipv6-proxy.conf << EOF
fs.file-max = 2097152
fs.nr_open = 2097152
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_max_tw_buckets = 2000000
net.netfilter.nf_conntrack_max = 2097152
net.nf_conntrack_max = 2097152
EOF

sysctl -p /etc/sysctl.d/ipv6-proxy.conf >/dev/null 2>&1 || true
print_success "系统参数优化完成"

# ==================== 第四步:安装 Go ====================
print_info "第 4 步:检查 Go 环境..."

export PATH=$PATH:/usr/local/go/bin
if ! command -v go &> /dev/null; then
    print_info "安装 Go..."
    cd /tmp
    wget -q --show-progress https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    print_success "Go 安装完成"
else
    print_success "Go 已安装: $(go version | awk '{print $3}')"
fi

# ==================== 第五步:创建程序 ====================
print_info "第 5 步:创建代理程序..."

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
CONFIG

cat > main.go << 'GOCODE'
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
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
	cfg                                                                    Config
	activeConns, totalConns, successConns, failedConns, bytesIn, bytesOut int64
	portSuccess, portFailed                                                int64
	bufferPool                                                             = sync.Pool{New: func() interface{} { return make([]byte, 32768) }}
	listeners                                                              = make([]net.Listener, 0)
	listenersMu                                                            sync.Mutex
	shutdownCtx, shutdownCancel                                            = context.WithCancel(context.Background())
)

type Config struct {
	StartPort, PortCount, MetricsPort, Username, Password, IPv6Prefix string
	IPv6Enabled                                                       bool
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
			}
		}
	}
	return nil
}

func randomIPv6() string {
	if !cfg.IPv6Enabled || cfg.IPv6Prefix == "" {
		return ""
	}
	return fmt.Sprintf("%s:%x:%x:%x:%x", cfg.IPv6Prefix,
		rand.Int31n(0x10000), rand.Int31n(0x10000), rand.Int31n(0x10000), rand.Int31n(0x10000))
}

func checkAuth(h string) bool {
	exp := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
	for _, l := range strings.Split(h, "\r\n") {
		if strings.HasPrefix(strings.ToLower(l), "proxy-authorization: basic ") && strings.TrimSpace(l[27:]) == exp {
			return true
		}
	}
	return false
}

// 修复 #2: 分离读写超时控制
func transfer(dst io.Writer, src io.Reader, dir string, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)
	
	for {
		// 只为读取端设置超时
		if conn, ok := src.(net.Conn); ok {
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		}
		
		n, err := src.Read(buf)
		if n > 0 {
			if dir == "up" {
				atomic.AddInt64(&bytesOut, int64(n))
			} else {
				atomic.AddInt64(&bytesIn, int64(n))
			}
			
			// 只为写入端设置超时
			if conn, ok := dst.(net.Conn); ok {
				conn.SetWriteDeadline(time.Now().Add(5 * time.Minute))
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

// 修复 #11: 正确的 SOCKS5 认证解析
func handleSOCKS5(c net.Conn, ipv6 string) error {
	buf := make([]byte, 512)
	
	// 1. 读取初始握手: [版本(5), 方法数量, 方法列表]
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 5 {
		return fmt.Errorf("invalid SOCKS version: %d", buf[0])
	}
	
	nMethods := int(buf[1])
	if _, err := io.ReadFull(c, buf[:nMethods]); err != nil {
		return err
	}
	
	// 2. 响应选择用户名/密码认证 (方法 0x02)
	c.Write([]byte{5, 2})
	
	// 3. 读取认证请求: [版本(1), 用户名长度, 用户名, 密码长度, 密码]
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 1 { // 认证子协议版本
		return fmt.Errorf("invalid auth version: %d", buf[0])
	}
	
	// 读取用户名
	userLen := int(buf[1])
	if _, err := io.ReadFull(c, buf[:userLen]); err != nil {
		return err
	}
	user := string(buf[:userLen])
	
	// 读取密码长度和密码
	if _, err := io.ReadFull(c, buf[:1]); err != nil {
		return err
	}
	passLen := int(buf[0])
	if _, err := io.ReadFull(c, buf[:passLen]); err != nil {
		return err
	}
	pass := string(buf[:passLen])
	
	// 4. 验证认证
	if user != cfg.Username || pass != cfg.Password {
		c.Write([]byte{1, 1}) // 认证失败
		return fmt.Errorf("auth failed")
	}
	c.Write([]byte{1, 0}) // 认证成功
	
	// 5. 读取连接请求: [版本, 命令, 保留, 地址类型, 目标地址, 目标端口]
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return err
	}
	
	var host string
	var port uint16
	
	// 解析目标地址
	if buf[3] == 1 { // IPv4
		if _, err := io.ReadFull(c, buf[:6]); err != nil {
			return err
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		port = binary.BigEndian.Uint16(buf[4:6])
	} else if buf[3] == 3 { // 域名
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
		host = net.IP(buf[:16]).String()
		port = binary.BigEndian.Uint16(buf[16:18])
	}
	
	return connectAndForward(c, host, port, ipv6, true)
}

// 修复 #7: 先验证认证再处理请求
func handleHTTP(c net.Conn, fb byte, ipv6 string) error {
	r := bufio.NewReader(io.MultiReader(strings.NewReader(string(fb)), c))
	
	// 1. 读取请求行
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return fmt.Errorf("invalid request")
	}
	
	// 2. 优先读取 Proxy-Authorization 头 (限制读取大小防止 DoS)
	var authHeader string
	headerCount := 0
	maxHeaders := 50 // 最多读取 50 行头
	
	for headerCount < maxHeaders {
		l, err := r.ReadString('\n')
		if err != nil {
			break
		}
		headerCount++
		
		// 找到认证头就立即验证
		if strings.HasPrefix(strings.ToLower(l), "proxy-authorization:") {
			authHeader = l
			break
		}
		
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	
	// 3. 验证认证
	if authHeader == "" || !checkAuth(authHeader) {
		c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
		return fmt.Errorf("auth failed")
	}
	
	// 4. 只支持 CONNECT 方法
	if parts[0] != "CONNECT" {
		c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return fmt.Errorf("method not allowed")
	}
	
	// 5. 解析目标地址
	hp := strings.Split(parts[1], ":")
	if len(hp) != 2 {
		return fmt.Errorf("invalid host:port")
	}
	var port uint16
	fmt.Sscanf(hp[1], "%d", &port)
	
	return connectAndForward(c, hp[0], port, ipv6, false)
}

// 判断是否可重试的错误
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// 只重试超时和临时网络错误
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "temporary") ||
		strings.Contains(errStr, "network is unreachable") {
		return true
	}
	return false
}

// 修复 #12: 正确处理 IPv6 路由
func connectAndForward(c net.Conn, host string, port uint16, ipv6 string, socks bool) error {
	var d net.Dialer
	d.Timeout = 30 * time.Second
	
	// 解析目标地址类型
	targetAddr := fmt.Sprintf("%s:%d", host, port)
	isIPv6Target := false
	
	if ip := net.ParseIP(host); ip != nil {
		isIPv6Target = ip.To4() == nil
	} else {
		// 域名需要先解析判断类型
		ips, err := net.LookupIP(host)
		if err == nil && len(ips) > 0 {
			isIPv6Target = ips[0].To4() == nil
		}
	}
	
	// 只有目标是 IPv6 时才绑定 IPv6 源地址
	if cfg.IPv6Enabled && ipv6 != "" && isIPv6Target {
		if addr, err := net.ResolveIPAddr("ip6", ipv6); err == nil {
			d.LocalAddr = &net.TCPAddr{IP: addr.IP}
		}
	}
	
	// 优化重试逻辑: 只对可重试错误重试
	var remote net.Conn
	var err error
	maxRetries := 3
	
	for retry := 0; retry < maxRetries; retry++ {
		remote, err = d.Dial("tcp", targetAddr)
		if err == nil {
			break
		}
		
		// 只对可重试错误进行重试
		if !isRetryableError(err) {
			break
		}
		
		if retry < maxRetries-1 {
			backoff := time.Duration(100*(1<<uint(retry))) * time.Millisecond
			time.Sleep(backoff)
		}
	}
	
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
	
	// 初始超时设置
	c.SetReadDeadline(time.Now().Add(5 * time.Minute))
	c.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	remote.SetReadDeadline(time.Now().Add(5 * time.Minute))
	remote.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	
	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(remote, c, "up", &wg)
	go transfer(c, remote, "down", &wg)
	wg.Wait()
	return nil
}

// 修复 #3: 添加 panic 恢复
func handleConn(c net.Conn) {
	atomic.AddInt64(&activeConns, 1)
	atomic.AddInt64(&totalConns, 1)
	
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] 连接处理崩溃: %v", r)
		}
		c.Close()
		atomic.AddInt64(&activeConns, -1)
	}()
	
	c.SetDeadline(time.Now().Add(30 * time.Second))
	
	ipv6 := randomIPv6()
	fb := make([]byte, 1)
	if _, err := c.Read(fb); err != nil {
		return
	}
	
	c.SetDeadline(time.Time{})
	
	if fb[0] == 0x05 {
		handleSOCKS5(c, ipv6)
	} else {
		handleHTTP(c, fb[0], ipv6)
	}
}

// 修复 #1: 同步检查关键端口
func startProxyServer(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		atomic.AddInt64(&portFailed, 1)
		return err
	}
	
	atomic.AddInt64(&portSuccess, 1)
	
	// 保存 listener 用于优雅关闭
	listenersMu.Lock()
	listeners = append(listeners, ln)
	listenersMu.Unlock()
	
	go func() {
		defer ln.Close()
		for {
			// 检查是否收到关闭信号
			select {
			case <-shutdownCtx.Done():
				return
			default:
			}
			
			// 设置 Accept 超时以便定期检查关闭信号
			if tcpLn, ok := ln.(*net.TCPListener); ok {
				tcpLn.SetDeadline(time.Now().Add(1 * time.Second))
			}
			
			conn, err := ln.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			go handleConn(conn)
		}
	}()
	return nil
}

func statsRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-shutdownCtx.Done():
			return
		case <-ticker.C:
			log.Printf("[统计] 活跃:%d 总计:%d 成功:%d 失败:%d 入站:%.2fGB 出站:%.2fGB",
				atomic.LoadInt64(&activeConns), atomic.LoadInt64(&totalConns),
				atomic.LoadInt64(&successConns), atomic.LoadInt64(&failedConns),
				float64(atomic.LoadInt64(&bytesIn))/1e9, float64(atomic.LoadInt64(&bytesOut))/1e9)
		}
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
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK\n")
	})
	
	srv := &http.Server{
		Addr:    ":" + cfg.MetricsPort,
		Handler: mux,
	}
	
	go func() {
		<-shutdownCtx.Done()
		srv.Shutdown(context.Background())
	}()
	
	srv.ListenAndServe()
}

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	rand.Seed(time.Now().UnixNano())
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	startPort, _ := strconv.Atoi(cfg.StartPort)
	portCount, _ := strconv.Atoi(cfg.PortCount)
	endPort := startPort + portCount - 1
	
	log.Printf("IPv6 Rotating Proxy (修复版) | 端口: %d-%d (%d个) | IPv6: %v", startPort, endPort, portCount, cfg.IPv6Enabled)
	
	go statsRoutine()
	go metricsServer()
	
	// 修复 #4: 批量启动端口 (每批 1000 个)
	log.Printf("正在启动 %d 个代理端口 (批量模式)...", portCount)
	batchSize := 1000
	failedPorts := make([]int, 0)
	
	for i := 0; i < portCount; i++ {
		port := startPort + i
		if err := startProxyServer(port); err != nil {
			failedPorts = append(failedPorts, port)
			log.Printf("端口 %d 启动失败: %v", port, err)
		}
		
		// 每批暂停一下,避免资源瞬时耗尽
		if (i+1)%batchSize == 0 {
			time.Sleep(100 * time.Millisecond)
			log.Printf("进度: %d/%d (%.1f%%)", i+1, portCount, float64(i+1)/float64(portCount)*100)
		} else if i == portCount-1 {
			log.Printf("进度: %d/%d (100.0%%)", i+1, portCount)
		}
	}
	
	time.Sleep(2 * time.Second)
	
	successCount := atomic.LoadInt64(&portSuccess)
	failedCount := atomic.LoadInt64(&portFailed)
	
	log.Printf("启动完成! 成功: %d | 失败: %d", successCount, failedCount)
	if len(failedPorts) > 0 && len(failedPorts) <= 20 {
		log.Printf("失败端口: %v", failedPorts)
	}
	
	// 如果超过 10% 的端口失败,发出警告
	if float64(failedCount)/float64(portCount) > 0.1 {
		log.Printf("[警告] 超过 10%% 的端口启动失败,请检查端口占用情况")
	}
	
	// 修复 #10: 优雅关闭机制
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	
	log.Printf("服务运行中,按 Ctrl+C 或发送 SIGTERM 优雅关闭...")
	<-sigChan
	
	log.Printf("收到关闭信号,开始优雅关闭...")
	
	// 1. 停止接受新连接
	shutdownCancel()
	
	listenersMu.Lock()
	log.Printf("关闭 %d 个监听端口...", len(listeners))
	for _, ln := range listeners {
		ln.Close()
	}
	listenersMu.Unlock()
	
	log.Printf("当前活跃连接: %d", atomic.LoadInt64(&activeConns))
	
	// 2. 等待现有连接完成 (最多 60 秒)
	shutdownTimeout := 60
	for i := 0; i < shutdownTimeout; i++ {
		active := atomic.LoadInt64(&activeConns)
		if active == 0 {
			log.Printf("所有连接已关闭")
			break
		}
		if i%5 == 0 {
			log.Printf("等待 %d 个连接关闭... (%d/%d秒)", active, i, shutdownTimeout)
		}
		time.Sleep(1 * time.Second)
	}
	
	finalActive := atomic.LoadInt64(&activeConns)
	if finalActive > 0 {
		log.Printf("超时强制关闭,剩余 %d 个连接", finalActive)
	}
	
	log.Printf("服务已关闭")
}
GOCODE

go mod init ipv6-proxy >/dev/null 2>&1 || true
go build -ldflags="-s -w" -o ipv6-proxy main.go
print_success "编译完成"

# ==================== 创建服务 ====================
cat > /etc/systemd/system/ipv6-proxy.service << EOF
[Unit]
Description=IPv6 Rotating Proxy (Multi-Port Fixed)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ipv6-proxy
ExecStart=/opt/ipv6-proxy/ipv6-proxy
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=1048576
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=90

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ipv6-proxy
systemctl start ipv6-proxy
sleep 5

# ==================== 完成 ====================
echo ""
echo "========================================="
print_success "安装完成! (修复版)"
echo "========================================="
echo ""
echo "服务器IP:  $IPV4"
echo "代理数量:  $PORT_COUNT 个"
echo "端口范围:  $START_PORT - $END_PORT"
echo "用户名:    $USERNAME"
echo "密码:      $PASSWORD"
echo ""
echo "修复项:"
echo "  ✓ #1  端口失败检测和报告"
echo "  ✓ #2  分离读写超时控制"
echo "  ✓ #4  批量启动限速 (1000/批)"
echo "  ✓ #7  认证优先验证"
echo "  ✓ #10 优雅关闭机制"
echo "  ✓ #11 SOCKS5 认证解析修复"
echo "  ✓ #12 IPv6 路由修复"
echo ""
echo "测试命令:"
echo "curl -x http://$USERNAME:$PASSWORD@$IPV4:$START_PORT http://ipv6.ip.sb"
echo ""
echo "监控: curl http://localhost:$METRICS_PORT/metrics"
echo "日志: journalctl -u ipv6-proxy -f"
echo "========================================="

systemctl status ipv6-proxy --no-pager | head -10
