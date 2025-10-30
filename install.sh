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
echo "  IPv6 智能代理 - 修复版 V2"
echo "  ✓ 修复SOCKS5解析BUG"
echo "  ✓ 修复清理进程问题"
echo "  ✓ 失败自动重试"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    print_error "请使用 root 权限运行"
    exit 1
fi

# ==================== 清理 ====================
print_info "第 1 步：清理现有服务..."
echo ""

# 🔧 修复：精确清理，只清理 ipv6-proxy 服务
if systemctl list-unit-files | grep -q "^ipv6-proxy.service"; then
    print_info "停止 ipv6-proxy 服务..."
    systemctl stop ipv6-proxy 2>/dev/null || true
    systemctl disable ipv6-proxy 2>/dev/null || true
    print_success "服务已停止"
fi

# 🔧 修复：只杀死特定的二进制文件
print_info "终止旧进程..."
pkill -9 -f "/opt/ipv6-proxy/ipv6-proxy" 2>/dev/null && print_success "已终止旧进程" || print_info "无旧进程"

# 释放端口
fuser -k 20000/tcp 2>/dev/null || true
fuser -k 20001/tcp 2>/dev/null || true
sleep 2
print_success "清理完成"

echo ""

# ==================== 配置 ====================
print_info "第 2 步：配置参数..."
echo ""

IPV4=$(curl -s -4 --max-time 3 ifconfig.me 2>/dev/null || echo "")
if [ -z "$IPV4" ]; then
    read -p "请输入服务器 IPv4: " IPV4
else
    print_success "检测到 IPv4: $IPV4"
    read -p "确认? [Y/n] " confirm
    [[ $confirm =~ ^[Nn]$ ]] && read -p "请输入 IPv4: " IPV4
fi

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

read -p "代理端口 [20000]: " PROXY_PORT
PROXY_PORT=${PROXY_PORT:-20000}
read -p "监控端口 [20001]: " METRICS_PORT
METRICS_PORT=${METRICS_PORT:-20001}

print_info "智能重试已启用（最大重试5次，失败IP自动封禁）"
MAX_PER_IP=1

read -p "用户名 [proxy]: " USERNAME
USERNAME=${USERNAME:-proxy}
read -sp "密码 [回车自动生成]: " PASSWORD
echo ""
[ -z "$PASSWORD" ] && PASSWORD=$(openssl rand -hex 6) && print_info "生成密码: $PASSWORD"

echo ""
echo "========================================="
echo "  配置摘要"
echo "========================================="
echo "服务器: $IPV4:$PROXY_PORT"
echo "用户名: $USERNAME"
echo "密码: $PASSWORD"
echo "每IP并发: 1 (智能重试模式)"
echo "最大重试: 5次"
$USE_IPV6 && echo "IPv6: $IPV6_PREFIX::/64" || echo "IPv6: 禁用"
echo "========================================="
echo ""

read -p "确认安装? [Y/n] " confirm
[[ $confirm =~ ^[Nn]$ ]] && exit 0

# ==================== 安装 ====================
print_info "第 3 步：安装..."
echo ""

export PATH=$PATH:/usr/local/go/bin
if ! command -v go &> /dev/null; then
    print_info "安装 Go 1.21.5..."
    cd /tmp
    wget -q --show-progress https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    print_success "Go 安装完成"
else
    print_success "Go 已安装: $(go version)"
fi

print_info "创建工作目录..."
rm -rf /opt/ipv6-proxy
mkdir -p /opt/ipv6-proxy /etc/ipv6-proxy
cd /opt/ipv6-proxy
print_success "目录创建完成"

print_info "生成配置文件..."
cat > /etc/ipv6-proxy/config.txt << CONFIG
PROXY_PORT=$PROXY_PORT
METRICS_PORT=$METRICS_PORT
USERNAME=$USERNAME
PASSWORD=$PASSWORD
IPV6_ENABLED=$USE_IPV6
IPV6_PREFIX=$IPV6_PREFIX
MAX_PER_IP=1
MAX_RETRIES=5
BLACKLIST_DURATION=300
CONFIG
print_success "配置文件: /etc/ipv6-proxy/config.txt"

print_info "创建智能代理程序（已修复BUG）..."

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
    "runtime"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

var (
    cfg Config
    ipConcurrency sync.Map
    ipBlacklist   sync.Map
    ipFailures    sync.Map
    
    activeConns, totalConns, successConns, failedConns int64
    retriedConns, blacklistedIPs int64
    bytesIn, bytesOut int64
    
    bufferPool = sync.Pool{New: func() interface{} { return make([]byte, 65536) }}
)

type Config struct {
    ProxyPort, MetricsPort, Username, Password, IPv6Prefix string
    IPv6Enabled                                            bool
    MaxPerIP                                               int
    MaxRetries                                             int
    BlacklistDuration                                      int
}

func loadConfig() {
    data, _ := os.ReadFile("/etc/ipv6-proxy/config.txt")
    cfg.MaxPerIP = 1
    cfg.MaxRetries = 5
    cfg.BlacklistDuration = 300
    
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
            case "MAX_RETRIES":
                fmt.Sscanf(val, "%d", &cfg.MaxRetries)
            case "BLACKLIST_DURATION":
                fmt.Sscanf(val, "%d", &cfg.BlacklistDuration)
            }
        }
    }
}

func randomIPv6() string {
    if !cfg.IPv6Enabled || cfg.IPv6Prefix == "" {
        return ""
    }
    return fmt.Sprintf("%s:%x:%x:%x:%x", cfg.IPv6Prefix,
        rand.Int31n(0x10000), rand.Int31n(0x10000), rand.Int31n(0x10000), rand.Int31n(0x10000))
}

func isBlacklisted(ip string) bool {
    if val, ok := ipBlacklist.Load(ip); ok {
        blockTime := val.(time.Time)
        if time.Since(blockTime) < time.Duration(cfg.BlacklistDuration)*time.Second {
            return true
        }
        ipBlacklist.Delete(ip)
        ipFailures.Delete(ip)
    }
    return false
}

func recordIPFailure(ip string) {
    if ip == "" {
        return
    }
    
    val, _ := ipFailures.LoadOrStore(ip, new(int32))
    failures := atomic.AddInt32(val.(*int32), 1)
    
    if failures >= 3 {
        ipBlacklist.Store(ip, time.Now())
        atomic.AddInt64(&blacklistedIPs, 1)
        log.Printf("[Blacklist] IP %s blocked after %d failures", ip, failures)
        ipFailures.Delete(ip)
    }
}

func recordIPSuccess(ip string) {
    if ip == "" {
        return
    }
    ipFailures.Delete(ip)
}

func acquireIPv6() string {
    if !cfg.IPv6Enabled {
        return ""
    }
    
    for i := 0; i < 200; i++ {
        ip := randomIPv6()
        
        if isBlacklisted(ip) {
            continue
        }
        
        val, _ := ipConcurrency.LoadOrStore(ip, new(int32))
        counter := val.(*int32)
        current := atomic.LoadInt32(counter)
        
        if current < int32(cfg.MaxPerIP) {
            atomic.AddInt32(counter, 1)
            return ip
        }
    }
    
    return randomIPv6()
}

func releaseIPv6(ip string) {
    if ip == "" {
        return
    }
    if val, ok := ipConcurrency.Load(ip); ok {
        atomic.AddInt32(val.(*int32), -1)
    }
}

func cleanupRoutine() {
    ticker := time.NewTicker(10 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        cleaned := 0
        
        ipConcurrency.Range(func(key, value interface{}) bool {
            if atomic.LoadInt32(value.(*int32)) == 0 {
                ipConcurrency.Delete(key)
                cleaned++
            }
            return true
        })
        
        expired := 0
        ipBlacklist.Range(func(key, value interface{}) bool {
            blockTime := value.(time.Time)
            if time.Since(blockTime) > time.Duration(cfg.BlacklistDuration)*time.Second {
                ipBlacklist.Delete(key)
                ipFailures.Delete(key)
                expired++
            }
            return true
        })
        
        if cleaned > 0 || expired > 0 {
            log.Printf("[Cleanup] Removed %d inactive IPs, %d expired blacklist entries", cleaned, expired)
        }
    }
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

func transfer(dst io.Writer, src io.Reader, dir string, wg *sync.WaitGroup) {
    defer wg.Done()
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    w, _ := io.CopyBuffer(dst, src, buf)
    if dir == "up" {
        atomic.AddInt64(&bytesOut, w)
    } else {
        atomic.AddInt64(&bytesIn, w)
    }
}

// 🔧 修复：正确的SOCKS5处理
func handleSOCKS5(c net.Conn) error {
    buf := make([]byte, 512)
    
    // 读取版本和方法数
    if _, err := io.ReadFull(c, buf[:2]); err != nil {
        return err
    }
    
    // 读取方法列表
    nMethods := int(buf[1])
    if _, err := io.ReadFull(c, buf[:nMethods]); err != nil {
        return err
    }
    
    // 响应：使用用户名/密码认证
    c.Write([]byte{5, 2})
    
    // 读取认证版本
    if _, err := io.ReadFull(c, buf[:2]); err != nil {
        return err
    }
    
    // 读取用户名
    userLen := int(buf[1])
    if _, err := io.ReadFull(c, buf[:userLen]); err != nil {
        return err
    }
    user := string(buf[:userLen])
    
    // 读取密码长度
    if _, err := io.ReadFull(c, buf[:1]); err != nil {
        return err
    }
    passLen := int(buf[0])
    
    // 读取密码
    if _, err := io.ReadFull(c, buf[:passLen]); err != nil {
        return err
    }
    pass := string(buf[:passLen])
    
    // 验证认证
    if user != cfg.Username || pass != cfg.Password {
        c.Write([]byte{1, 1})
        return fmt.Errorf("auth failed")
    }
    c.Write([]byte{1, 0})
    
    // 读取连接请求
    if _, err := io.ReadFull(c, buf[:4]); err != nil {
        return err
    }
    
    var host string
    var port uint16
    
    atyp := buf[3]
    
    if atyp == 1 { // IPv4
        if _, err := io.ReadFull(c, buf[:4]); err != nil {
            return err
        }
        host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
        if _, err := io.ReadFull(c, buf[:2]); err != nil {
            return err
        }
        port = binary.BigEndian.Uint16(buf[:2])
    } else if atyp == 3 { // 域名
        if _, err := io.ReadFull(c, buf[:1]); err != nil {
            return err
        }
        dlen := int(buf[0])
        if _, err := io.ReadFull(c, buf[:dlen]); err != nil {
            return err
        }
        host = string(buf[:dlen])
        if _, err := io.ReadFull(c, buf[:2]); err != nil {
            return err
        }
        port = binary.BigEndian.Uint16(buf[:2])
    } else if atyp == 4 { // IPv6
        if _, err := io.ReadFull(c, buf[:16]); err != nil {
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
        if _, err := io.ReadFull(c, buf[:2]); err != nil {
            return err
        }
        port = binary.BigEndian.Uint16(buf[:2])
    } else {
        return fmt.Errorf("unsupported address type: %d", atyp)
    }
    
    return connectWithRetry(c, host, port, true)
}

func handleHTTP(c net.Conn, fb byte) error {
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
    
    return connectWithRetry(c, hp[0], port, false)
}

func connectWithRetry(c net.Conn, host string, port uint16, socks bool) error {
    var lastErr error
    
    for attempt := 0; attempt < cfg.MaxRetries; attempt++ {
        if attempt > 0 {
            atomic.AddInt64(&retriedConns, 1)
            time.Sleep(time.Duration(100+rand.Intn(200)) * time.Millisecond)
        }
        
        ipv6 := acquireIPv6()
        
        err := connectAndForward(c, host, port, ipv6, socks)
        
        if err == nil {
            recordIPSuccess(ipv6)
            releaseIPv6(ipv6)
            return nil
        }
        
        lastErr = err
        recordIPFailure(ipv6)
        releaseIPv6(ipv6)
        
        if !isNetworkError(err) {
            break
        }
    }
    
    atomic.AddInt64(&failedConns, 1)
    if socks {
        c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
    } else {
        c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
    }
    return lastErr
}

func isNetworkError(err error) bool {
    if err == nil {
        return false
    }
    errStr := err.Error()
    return strings.Contains(errStr, "timeout") ||
           strings.Contains(errStr, "connection refused") ||
           strings.Contains(errStr, "network unreachable") ||
           strings.Contains(errStr, "no route to host")
}

func connectAndForward(c net.Conn, host string, port uint16, ipv6 string, socks bool) error {
    var d net.Dialer
    if cfg.IPv6Enabled && ipv6 != "" {
        if addr, err := net.ResolveIPAddr("ip6", ipv6); err == nil {
            d.LocalAddr = &net.TCPAddr{IP: addr.IP}
        }
    }
    d.Timeout = 15 * time.Second
    
    remote, err := d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
    if err != nil {
        return err
    }
    defer remote.Close()
    
    if tcp, ok := remote.(*net.TCPConn); ok {
        tcp.SetNoDelay(true)
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
    atomic.AddInt64(&activeConns, 1)
    atomic.AddInt64(&totalConns, 1)
    
    c.SetDeadline(time.Now().Add(5 * time.Minute))
    
    fb := make([]byte, 1)
    if _, err := c.Read(fb); err != nil {
        return
    }
    
    if fb[0] == 0x05 {
        if err := handleSOCKS5(c); err != nil {
            log.Printf("[Error] SOCKS5: %v", err)
        }
    } else {
        if err := handleHTTP(c, fb[0]); err != nil {
            log.Printf("[Error] HTTP: %v", err)
        }
    }
}

func statsRoutine() {
    t := time.NewTicker(30 * time.Second)
    defer t.Stop()
    for range t.C {
        ipCount := 0
        blacklistCount := 0
        
        ipConcurrency.Range(func(key, value interface{}) bool {
            if atomic.LoadInt32(value.(*int32)) > 0 {
                ipCount++
            }
            return true
        })
        
        ipBlacklist.Range(func(key, value interface{}) bool {
            blacklistCount++
            return true
        })
        
        log.Printf("[Stats] Conn: A=%d T=%d S=%d F=%d R=%d | IPv6: Active=%d Blacklist=%d | Traffic: In=%.1fM Out=%.1fM | Go=%d",
            atomic.LoadInt64(&activeConns), atomic.LoadInt64(&totalConns),
            atomic.LoadInt64(&successConns), atomic.LoadInt64(&failedConns),
            atomic.LoadInt64(&retriedConns),
            ipCount, blacklistCount,
            float64(atomic.LoadInt64(&bytesIn))/1e6, float64(atomic.LoadInt64(&bytesOut))/1e6,
            runtime.NumGoroutine())
    }
}

func metricsServer() {
    mux := http.NewServeMux()
    mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
        ipCount := 0
        blacklistCount := 0
        
        ipConcurrency.Range(func(key, value interface{}) bool {
            if atomic.LoadInt32(value.(*int32)) > 0 {
                ipCount++
            }
            return true
        })
        
        ipBlacklist.Range(func(key, value interface{}) bool {
            blacklistCount++
            return true
        })
        
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        
        fmt.Fprintf(w, "proxy_active %d\nproxy_total %d\nproxy_success %d\nproxy_failed %d\nproxy_retried %d\n",
            atomic.LoadInt64(&activeConns), atomic.LoadInt64(&totalConns),
            atomic.LoadInt64(&successConns), atomic.LoadInt64(&failedConns),
            atomic.LoadInt64(&retriedConns))
        fmt.Fprintf(w, "ipv6_active %d\nipv6_blacklist %d\nipv6_blacklisted_total %d\n",
            ipCount, blacklistCount, atomic.LoadInt64(&blacklistedIPs))
        fmt.Fprintf(w, "goroutines %d\nmemory_mb %.2f\n",
            runtime.NumGoroutine(), float64(m.Alloc)/1024/1024)
    })
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "OK\n")
    })
    http.ListenAndServe(":"+cfg.MetricsPort, mux)
}

func main() {
    loadConfig()
    rand.Seed(time.Now().UnixNano())
    runtime.GOMAXPROCS(runtime.NumCPU())
    
    log.Printf("🚀 IPv6 Smart Proxy V2 | Port:%s Metrics:%s IPv6:%v MaxRetries:%d", 
        cfg.ProxyPort, cfg.MetricsPort, cfg.IPv6Enabled, cfg.MaxRetries)
    
    go cleanupRoutine()
    go statsRoutine()
    go metricsServer()
    
    ln, err := net.Listen("tcp", ":"+cfg.ProxyPort)
    if err != nil {
        log.Fatalf("Failed to listen: %v", err)
    }
    defer ln.Close()
    
    log.Printf("✅ Proxy server started successfully")
    
    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("Accept error: %v", err)
            time.Sleep(time.Second)
            continue
        }
        go handleConn(conn)
    }
}
GOCODE

print_success "修复版源代码创建完成"

print_info "编译 Go 程序..."
go mod init ipv6-proxy >/dev/null 2>&1
go build -ldflags="-s -w" -o ipv6-proxy main.go
if [ $? -eq 0 ]; then
    print_success "编译完成"
else
    print_error "编译失败"
    exit 1
fi

print_info "创建 systemd 服务..."
cat > /etc/systemd/system/ipv6-proxy.service << 'SERVICE'
[Unit]
Description=IPv6 Smart Proxy V2
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ipv6-proxy
ExecStart=/opt/ipv6-proxy/ipv6-proxy
Restart=always
RestartSec=3
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
SERVICE

print_info "启动服务..."
systemctl daemon-reload
systemctl enable ipv6-proxy
systemctl start ipv6-proxy
print_success "服务已启动"

sleep 3

echo ""
echo "========================================="
print_success "修复版安装完成！"
echo "========================================="
echo ""
echo "🔧 修复的BUG:"
echo "  ✓ SOCKS5协议解析错误"
echo "  ✓ 进程清理过于激进"
echo "  ✓ 增加错误处理和日志"
echo ""
echo "📍 代理地址: $IPV4:$PROXY_PORT"
echo "👤 用户名: $USERNAME"
echo "🔑 密码: $PASSWORD"
echo ""
echo "🎯 智能特性:"
echo "  ✓ 每IP并发: 1"
echo "  ✓ 自动重试: 最多5次"
echo "  ✓ IP黑名单: 连续失败3次封禁5分钟"
echo "  ✓ 自动清理: 每10分钟"
$USE_IPV6 && echo "  ✓ IPv6池: $IPV6_PREFIX::/64" || echo "  ⚠ IPv6: 禁用"
echo ""
echo "🧪 测试命令:"
echo "  # SOCKS5测试"
echo "  curl -x socks5://$USERNAME:$PASSWORD@$IPV4:$PROXY_PORT http://ipv6.ip.sb"
echo ""
echo "  # HTTP测试"
echo "  curl -x http://$USERNAME:$PASSWORD@$IPV4:$PROXY_PORT https://api.ip.sb/ip"
echo ""
echo "📊 监控命令:"
echo "  curl http://localhost:$METRICS_PORT/metrics"
echo ""
echo "📝 查看日志:"
echo "  journalctl -u ipv6-proxy -f"
echo "  journalctl -u ipv6-proxy | grep Blacklist"
echo "  journalctl -u ipv6-proxy | grep Cleanup"
echo ""

print_info "当前服务状态:"
systemctl status ipv6-proxy --no-pager -l | head -15
