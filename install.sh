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
echo "  IPv6 Rotating Proxy"
echo "  百万并发 + IP不复用"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    print_error "请使用 root 权限运行"
    exit 1
fi

# ==================== 第一步：彻底清理 ====================
print_info "第 1 步：彻底清理现有服务和进程..."
echo ""

print_info "当前运行的代理相关服务："
systemctl list-units --type=service --state=running | grep -E "(proxy|ipv6)" || echo "  无"

print_info "当前运行的代理相关进程："
ps aux | grep -E "(proxy|python.*20000)" | grep -v grep | head -5 || echo "  无"

print_info "当前端口占用："
lsof -i :20000 2>/dev/null | tail -n +2 || echo "  20000: 空闲"
lsof -i :20001 2>/dev/null | tail -n +2 || echo "  20001: 空闲"

echo ""
read -p "开始清理? [Y/n] " start_clean
if [[ $start_clean =~ ^[Nn]$ ]]; then
    exit 0
fi

print_info "停止所有代理服务..."
for service in go-proxy ipv6-proxy dynamic-proxy python-proxy; do
    if systemctl list-unit-files | grep -q "^$service.service"; then
        systemctl stop $service 2>/dev/null || true
        systemctl disable $service 2>/dev/null || true
        rm -f /etc/systemd/system/$service.service
        print_success "已清理: $service"
    fi
done

systemctl daemon-reload

print_info "终止所有代理进程..."
pkill -9 -f "proxy-server" 2>/dev/null && print_success "已终止: proxy-server" || true
pkill -9 -f "ipv6-proxy" 2>/dev/null && print_success "已终止: ipv6-proxy" || true
pkill -9 -f "python.*proxy" 2>/dev/null && print_success "已终止: Python 代理" || true
pkill -9 -f "python.*20000" 2>/dev/null && print_success "已终止: Python 20000" || true

print_info "释放端口..."
for port in 20000 20001; do
    fuser -k $port/tcp 2>/dev/null && print_success "已释放端口: $port" || true
done

sleep 3

print_info "验证清理结果..."
if pgrep -f "proxy" >/dev/null || lsof -i :20000 >/dev/null 2>&1; then
    print_warning "仍有残留，再次清理..."
    pkill -9 -f "proxy" 2>/dev/null || true
    fuser -k -9 20000/tcp 2>/dev/null || true
    fuser -k -9 20001/tcp 2>/dev/null || true
    sleep 2
fi

print_success "清理完成"
echo ""

# ==================== 第二步：交互式配置 ====================
print_info "第 2 步：配置参数..."
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
if ping6 -c 1 -W 2 2001:4860:4860::8888 &>/dev/null; then
    IPV6_ADDR=$(ip -6 addr show scope global 2>/dev/null | grep inet6 | head -1 | awk '{print $2}' | cut -d'/' -f1)
    if [ -n "$IPV6_ADDR" ]; then
        IPV6_PREFIX=$(echo "$IPV6_ADDR" | cut -d':' -f1-4)
        print_success "检测到 IPv6: $IPV6_PREFIX::/64"
        read -p "启用 IPv6 轮换? [Y/n] " use_ipv6
        [[ $use_ipv6 =~ ^[Nn]$ ]] && USE_IPV6=false || USE_IPV6=true
    else
        USE_IPV6=false
    fi
else
    print_warning "IPv6 不可用"
    USE_IPV6=false
    IPV6_PREFIX=""
fi

# 端口
read -p "代理端口 [20000]: " PROXY_PORT
PROXY_PORT=${PROXY_PORT:-20000}
read -p "监控端口 [20001]: " METRICS_PORT
METRICS_PORT=${METRICS_PORT:-20001}

# 认证
read -p "用户名 [proxy]: " USERNAME
USERNAME=${USERNAME:-proxy}
read -sp "密码 [回车自动生成]: " PASSWORD
echo ""
[ -z "$PASSWORD" ] && PASSWORD=$(openssl rand -hex 6) && print_info "生成密码: $PASSWORD"

# 确认
echo ""
echo "========================================="
echo "  配置摘要"
echo "========================================="
echo "服务器: $IPV4:$PROXY_PORT"
echo "用户名: $USERNAME"
echo "密码: $PASSWORD"
echo "模式: 百万并发 + IP一次性使用"
$USE_IPV6 && echo "IPv6: $IPV6_PREFIX::/64" || echo "IPv6: 禁用"
echo "========================================="
echo ""

read -p "确认安装? [Y/n] " confirm
[[ $confirm =~ ^[Nn]$ ]] && exit 0

# ==================== 系统优化 ====================
print_info "第 3 步：系统优化（百万并发）..."
echo ""

print_info "优化系统参数..."

# 备份原配置
cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%s) 2>/dev/null || true
cp /etc/security/limits.conf /etc/security/limits.conf.backup.$(date +%s) 2>/dev/null || true

# sysctl 优化
cat >> /etc/sysctl.conf << 'SYSCTL'

# IPv6 Proxy - 百万并发优化
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mem = 786432 1048576 26777216
fs.file-max = 2097152
fs.nr_open = 2097152
net.nf_conntrack_max = 2097152
SYSCTL

sysctl -p >/dev/null 2>&1 || true
print_success "sysctl 优化完成"

# limits 优化
cat >> /etc/security/limits.conf << 'LIMITS'

# IPv6 Proxy - 百万并发优化
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
root soft nofile 1048576
root hard nofile 1048576
root soft nproc 1048576
root hard nproc 1048576
LIMITS

print_success "limits 优化完成"

# PAM 配置
if ! grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null; then
    echo "session required pam_limits.so" >> /etc/pam.d/common-session 2>/dev/null || true
fi

print_success "系统优化完成"
echo ""

# ==================== 第四步：安装 ====================
print_info "第 4 步：安装..."
echo ""

# Go
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
fi

# 创建目录
rm -rf /opt/ipv6-proxy
mkdir -p /opt/ipv6-proxy /etc/ipv6-proxy
cd /opt/ipv6-proxy

# 创建配置
cat > /etc/ipv6-proxy/config.txt << CONFIG
PROXY_PORT=$PROXY_PORT
METRICS_PORT=$METRICS_PORT
USERNAME=$USERNAME
PASSWORD=$PASSWORD
IPV6_ENABLED=$USE_IPV6
IPV6_PREFIX=$IPV6_PREFIX
CONFIG

# 创建程序
print_info "创建高性能代理程序（百万并发 + IP不复用）..."

cat > main.go << 'GOCODE'
package main

import (
    "bufio"
    "crypto/rand"
    "encoding/base64"
    "encoding/binary"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "runtime"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

var (
    cfg         Config
    activeConns, totalConns, successConns, failedConns int64
    bytesIn, bytesOut, ipv6Generated int64
    bufferPool = sync.Pool{New: func() interface{} { return make([]byte, 32768) }}
    authCache  = make(map[string]bool)
    authMutex  sync.RWMutex
)

type Config struct {
    ProxyPort, MetricsPort, Username, Password, IPv6Prefix string
    IPv6Enabled                                            bool
}

func loadConfig() {
    data, _ := os.ReadFile("/etc/ipv6-proxy/config.txt")
    for _, line := range strings.Split(string(data), "\n") {
        parts := strings.SplitN(line, "=", 2)
        if len(parts) == 2 {
            key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
            switch key {
            case "PROXY_PORT":
                cfg.ProxyPort = val
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
}

// 高性能随机 IPv6 生成（使用 crypto/rand 确保唯一性）
func generateUniqueIPv6() string {
    if !cfg.IPv6Enabled || cfg.IPv6Prefix == "" {
        return ""
    }
    
    var suffix [8]byte
    rand.Read(suffix[:])
    
    atomic.AddInt64(&ipv6Generated, 1)
    
    return fmt.Sprintf("%s:%x:%x:%x:%x", 
        cfg.IPv6Prefix,
        binary.BigEndian.Uint16(suffix[0:2]),
        binary.BigEndian.Uint16(suffix[2:4]),
        binary.BigEndian.Uint16(suffix[4:6]),
        binary.BigEndian.Uint16(suffix[6:8]))
}

func checkAuth(h string) bool {
    exp := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
    authMutex.RLock()
    cached, exists := authCache[exp]
    authMutex.RUnlock()
    
    if exists {
        return cached
    }
    
    result := false
    for _, l := range strings.Split(h, "\r\n") {
        if strings.HasPrefix(strings.ToLower(l), "proxy-authorization: basic ") {
            if strings.TrimSpace(l[27:]) == exp {
                result = true
                break
            }
        }
    }
    
    authMutex.Lock()
    authCache[exp] = result
    authMutex.Unlock()
    
    return result
}

func transfer(dst io.Writer, src io.Reader, dir string, wg *sync.WaitGroup) {
    defer wg.Done()
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    
    written, _ := io.CopyBuffer(dst, src, buf)
    
    if dir == "up" {
        atomic.AddInt64(&bytesOut, written)
    } else {
        atomic.AddInt64(&bytesIn, written)
    }
}

func handleSOCKS5(c net.Conn, ipv6 string) error {
    buf := make([]byte, 512)
    
    // 握手
    if _, err := io.ReadFull(c, buf[:2]); err != nil {
        return err
    }
    nMethods := int(buf[1])
    if _, err := io.ReadFull(c, buf[:nMethods]); err != nil {
        return err
    }
    
    c.Write([]byte{5, 2}) // 需要用户名密码
    
    // 认证
    if _, err := io.ReadFull(c, buf[:2]); err != nil {
        return err
    }
    uLen := int(buf[1])
    if _, err := io.ReadFull(c, buf[:uLen]); err != nil {
        return err
    }
    user := string(buf[:uLen])
    
    if _, err := io.ReadFull(c, buf[:1]); err != nil {
        return err
    }
    pLen := int(buf[0])
    if _, err := io.ReadFull(c, buf[:pLen]); err != nil {
        return err
    }
    pass := string(buf[:pLen])
    
    if user != cfg.Username || pass != cfg.Password {
        c.Write([]byte{1, 1})
        return fmt.Errorf("auth failed")
    }
    c.Write([]byte{1, 0})
    
    // 请求
    if _, err := io.ReadFull(c, buf[:4]); err != nil {
        return err
    }
    
    var host string
    var port uint16
    
    atyp := buf[3]
    if atyp == 1 { // IPv4
        if _, err := io.ReadFull(c, buf[:6]); err != nil {
            return err
        }
        host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
        port = binary.BigEndian.Uint16(buf[4:6])
    } else if atyp == 3 { // 域名
        if _, err := io.ReadFull(c, buf[:1]); err != nil {
            return err
        }
        dLen := int(buf[0])
        if _, err := io.ReadFull(c, buf[:dLen+2]); err != nil {
            return err
        }
        host = string(buf[:dLen])
        port = binary.BigEndian.Uint16(buf[dLen : dLen+2])
    } else {
        c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
        return fmt.Errorf("unsupported atyp")
    }
    
    return connectAndForward(c, host, port, ipv6, true)
}

func handleHTTP(c net.Conn, fb byte, ipv6 string) error {
    r := bufio.NewReader(io.MultiReader(strings.NewReader(string(fb)), c))
    line, _ := r.ReadString('\n')
    parts := strings.Fields(line)
    
    if len(parts) < 2 {
        return fmt.Errorf("invalid request")
    }
    
    var h strings.Builder
    for {
        l, _ := r.ReadString('\n')
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
    
    var port uint16
    fmt.Sscanf(hp[1], "%d", &port)
    
    return connectAndForward(c, hp[0], port, ipv6, false)
}

func connectAndForward(c net.Conn, host string, port uint16, ipv6 string, socks bool) error {
    var d net.Dialer
    
    // 绑定唯一的 IPv6
    if cfg.IPv6Enabled && ipv6 != "" {
        if addr, err := net.ResolveIPAddr("ip6", ipv6); err == nil {
            d.LocalAddr = &net.TCPAddr{IP: addr.IP}
        }
    }
    
    d.Timeout = 10 * time.Second
    
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
    
    var wg sync.WaitGroup
    wg.Add(2)
    go transfer(remote, c, "up", &wg)
    go transfer(c, remote, "down", &wg)
    wg.Wait()
    
    return nil
}

func handleConn(c net.Conn) {
    defer c.Close()
    defer atomic.AddInt64(&activeConns, -1)
    
    // 设置连接参数
    if tcp, ok := c.(*net.TCPConn); ok {
        tcp.SetNoDelay(true)
        tcp.SetKeepAlive(false)
    }
    
    atomic.AddInt64(&activeConns, 1)
    atomic.AddInt64(&totalConns, 1)
    
    // 每个连接生成唯一的 IPv6
    ipv6 := generateUniqueIPv6()
    
    fb := make([]byte, 1)
    if _, err := c.Read(fb); err != nil {
        return
    }
    
    if fb[0] == 0x05 {
        handleSOCKS5(c, ipv6)
    } else {
        handleHTTP(c, fb[0], ipv6)
    }
}

func statsRoutine() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    var lastTotal, lastSuccess, lastFailed int64
    lastTime := time.Now()
    
    for range ticker.C {
        now := time.Now()
        elapsed := now.Sub(lastTime).Seconds()
        
        currentTotal := atomic.LoadInt64(&totalConns)
        currentSuccess := atomic.LoadInt64(&successConns)
        currentFailed := atomic.LoadInt64(&failedConns)
        
        reqPerSec := float64(currentTotal-lastTotal) / elapsed
        successPerSec := float64(currentSuccess-lastSuccess) / elapsed
        failedPerSec := float64(currentFailed-lastFailed) / elapsed
        
        log.Printf("[Stats] Active=%d Total=%d (%.1f/s) Success=%d (%.1f/s) Failed=%d (%.1f/s) | IPv6=%d | Traffic: In=%.1fGB Out=%.1fGB",
            atomic.LoadInt64(&activeConns),
            currentTotal, reqPerSec,
            currentSuccess, successPerSec,
            currentFailed, failedPerSec,
            atomic.LoadInt64(&ipv6Generated),
            float64(atomic.LoadInt64(&bytesIn))/1e9,
            float64(atomic.LoadInt64(&bytesOut))/1e9)
        
        lastTotal = currentTotal
        lastSuccess = currentSuccess
        lastFailed = currentFailed
        lastTime = now
    }
}

func metricsServer() {
    mux := http.NewServeMux()
    
    mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "proxy_active_connections %d\n", atomic.LoadInt64(&activeConns))
        fmt.Fprintf(w, "proxy_total_connections %d\n", atomic.LoadInt64(&totalConns))
        fmt.Fprintf(w, "proxy_success_connections %d\n", atomic.LoadInt64(&successConns))
        fmt.Fprintf(w, "proxy_failed_connections %d\n", atomic.LoadInt64(&failedConns))
        fmt.Fprintf(w, "proxy_ipv6_generated %d\n", atomic.LoadInt64(&ipv6Generated))
        fmt.Fprintf(w, "proxy_bytes_in %d\n", atomic.LoadInt64(&bytesIn))
        fmt.Fprintf(w, "proxy_bytes_out %d\n", atomic.LoadInt64(&bytesOut))
    })
    
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "OK\n")
    })
    
    mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "IPv6 Proxy Stats\n")
        fmt.Fprintf(w, "================\n")
        fmt.Fprintf(w, "Active Connections: %d\n", atomic.LoadInt64(&activeConns))
        fmt.Fprintf(w, "Total Connections: %d\n", atomic.LoadInt64(&totalConns))
        fmt.Fprintf(w, "Success: %d\n", atomic.LoadInt64(&successConns))
        fmt.Fprintf(w, "Failed: %d\n", atomic.LoadInt64(&failedConns))
        fmt.Fprintf(w, "IPv6 Generated: %d (unique)\n", atomic.LoadInt64(&ipv6Generated))
        fmt.Fprintf(w, "Traffic In: %.2f GB\n", float64(atomic.LoadInt64(&bytesIn))/1e9)
        fmt.Fprintf(w, "Traffic Out: %.2f GB\n", float64(atomic.LoadInt64(&bytesOut))/1e9)
        fmt.Fprintf(w, "Success Rate: %.2f%%\n", 
            float64(atomic.LoadInt64(&successConns))*100/float64(atomic.LoadInt64(&totalConns)+1))
    })
    
    server := &http.Server{
        Addr:         ":" + cfg.MetricsPort,
        Handler:      mux,
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 5 * time.Second,
    }
    
    log.Fatal(server.ListenAndServe())
}

func main() {
    loadConfig()
    
    // 性能优化
    runtime.GOMAXPROCS(runtime.NumCPU())
    
    log.Printf("IPv6 High-Performance Proxy Starting...")
    log.Printf("  Port: %s", cfg.ProxyPort)
    log.Printf("  Metrics: %s", cfg.MetricsPort)
    log.Printf("  IPv6: %v", cfg.IPv6Enabled)
    log.Printf("  Mode: Unique IP per connection (百万并发优化)")
    log.Printf("  CPU Cores: %d", runtime.NumCPU())
    
    go statsRoutine()
    go metricsServer()
    
    // 监听配置
    ln, err := net.Listen("tcp", ":"+cfg.ProxyPort)
    if err != nil {
        log.Fatal(err)
    }
    defer ln.Close()
    
    log.Printf("Proxy server listening on :%s", cfg.ProxyPort)
    
    // 接受连接
    for {
        conn, err := ln.Accept()
        if err != nil {
            continue
        }
        go handleConn(conn)
    }
}
GOCODE

# 编译
print_info "编译程序..."
go mod init ipv6-proxy >/dev/null 2>&1
go build -ldflags="-s -w" -o ipv6-proxy main.go
print_success "编译完成"

# systemd
cat > /etc/systemd/system/ipv6-proxy.service << 'SERVICE'
[Unit]
Description=IPv6 High-Performance Proxy (Million Concurrent)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ipv6-proxy
ExecStart=/opt/ipv6-proxy/ipv6-proxy
Restart=always
RestartSec=3
LimitNOFILE=2097152
LimitNPROC=2097152

[Install]
WantedBy=multi-user.target
SERVICE

# 启动
systemctl daemon-reload
systemctl enable ipv6-proxy
systemctl start ipv6-proxy

sleep 3

# 完成
echo ""
echo "========================================="
print_success "安装完成！"
echo "========================================="
echo ""
echo "代理: $IPV4:$PROXY_PORT"
echo "用户: $USERNAME"
echo "密码: $PASSWORD"
echo "模式: 百万并发 + IP不复用"
$USE_IPV6 && echo "IPv6: $IPV6_PREFIX::/64 (每连接唯一IP)"
echo ""
echo "测试:"
echo "  curl -x http://$USERNAME:$PASSWORD@$IPV4:$PROXY_PORT http://ipv6.ip.sb"
echo ""
echo "监控:"
echo "  curl http://localhost:$METRICS_PORT/stats"
echo "  curl http://localhost:$METRICS_PORT/metrics"
echo ""
echo "日志:"
echo "  journalctl -u ipv6-proxy -f"
echo ""
echo "性能验证:"
echo "  ab -n 10000 -c 1000 -X $IPV4:$PROXY_PORT http://example.com/"
echo ""

systemctl status ipv6-proxy --no-pager -l | head -15
