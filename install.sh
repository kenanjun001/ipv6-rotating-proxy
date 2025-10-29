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
echo "  完全清理 & 全新安装"
echo "  支持单IP并发限制"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    print_error "请使用 root 权限运行"
    exit 1
fi

# ==================== 第一步：彻底清理 ====================
print_info "第 1 步：彻底清理现有服务和进程..."
echo ""

# 显示当前状态
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
    print_warning "跳过清理，继续安装..."
else
    # 停止所有服务
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

    # 终止所有进程
    print_info "终止所有代理进程..."
    pkill -9 -f "proxy-server" 2>/dev/null && print_success "已终止: proxy-server" || true
    pkill -9 -f "ipv6-proxy" 2>/dev/null && print_success "已终止: ipv6-proxy" || true
    pkill -9 -f "python.*proxy" 2>/dev/null && print_success "已终止: Python 代理" || true
    pkill -9 -f "python.*20000" 2>/dev/null && print_success "已终止: Python 20000" || true

    # 强制释放端口
    print_info "释放端口..."
    for port in 20000 20001; do
        fuser -k $port/tcp 2>/dev/null && print_success "已释放端口: $port" || true
    done

    sleep 3

    # 验证清理
    print_info "验证清理结果..."
    if pgrep -f "proxy" >/dev/null || lsof -i :20000 >/dev/null 2>&1; then
        print_warning "仍有残留，再次清理..."
        pkill -9 -f "proxy" 2>/dev/null || true
        fuser -k -9 20000/tcp 2>/dev/null || true
        fuser -k -9 20001/tcp 2>/dev/null || true
        sleep 2
    fi

    print_success "清理完成"
fi

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

# 并发限制
read -p "每个IP最大并发数 [5]: " MAX_PER_IP
MAX_PER_IP=${MAX_PER_IP:-5}

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
echo "每IP并发: $MAX_PER_IP"
$USE_IPV6 && echo "IPv6: $IPV6_PREFIX::/64" || echo "IPv6: 禁用"
echo "========================================="
echo ""

read -p "确认安装? [Y/n] " confirm
[[ $confirm =~ ^[Nn]$ ]] && exit 0

# ==================== 第三步：安装 ====================
print_info "第 3 步：安装..."
echo ""

# Go
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

# 创建目录
print_info "创建工作目录..."
rm -rf /opt/ipv6-proxy
mkdir -p /opt/ipv6-proxy /etc/ipv6-proxy
cd /opt/ipv6-proxy
print_success "目录创建完成"

# 创建配置
print_info "生成配置文件..."
cat > /etc/ipv6-proxy/config.txt << CONFIG
PROXY_PORT=$PROXY_PORT
METRICS_PORT=$METRICS_PORT
USERNAME=$USERNAME
PASSWORD=$PASSWORD
IPV6_ENABLED=$USE_IPV6
IPV6_PREFIX=$IPV6_PREFIX
MAX_PER_IP=$MAX_PER_IP
CONFIG
print_success "配置文件: /etc/ipv6-proxy/config.txt"

# 创建程序
print_info "创建代理程序（已修复所有bug）..."

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
    activeConns, totalConns, successConns, failedConns, bytesIn, bytesOut int64
    ipRetries int64
    bufferPool = sync.Pool{New: func() interface{} { return make([]byte, 65536) }}
)

type Config struct {
    ProxyPort, MetricsPort, Username, Password, IPv6Prefix string
    IPv6Enabled                                            bool
    MaxPerIP                                               int
}

func loadConfig() {
    data, _ := os.ReadFile("/etc/ipv6-proxy/config.txt")
    cfg.MaxPerIP = 5
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
            case "MAX_PER_IP":
                fmt.Sscanf(val, "%d", &cfg.MaxPerIP)
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

func acquireIPv6() string {
    if !cfg.IPv6Enabled {
        return ""
    }
    for i := 0; i < 100; i++ {
        ip := randomIPv6()
        val, _ := ipConcurrency.LoadOrStore(ip, new(int32))
        counter := val.(*int32)
        current := atomic.LoadInt32(counter)
        if current < int32(cfg.MaxPerIP) {
            atomic.AddInt32(counter, 1)
            if i > 0 {
                atomic.AddInt64(&ipRetries, int64(i))
            }
            return ip
        }
    }
    ip := randomIPv6()
    val, _ := ipConcurrency.LoadOrStore(ip, new(int32))
    atomic.AddInt32(val.(*int32), 1)
    atomic.AddInt64(&ipRetries, 100)
    return ip
}

func releaseIPv6(ip string) {
    if ip == "" {
        return
    }
    if val, ok := ipConcurrency.Load(ip); ok {
        atomic.AddInt32(val.(*int32), -1)
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

func handleSOCKS5(c net.Conn, ipv6 string) error {
    defer releaseIPv6(ipv6)
    buf := make([]byte, 512)
    
    n, err := c.Read(buf)
    if err != nil || n < 2 {
        return err
    }
    if buf[0] != 5 {
        return fmt.Errorf("ver")
    }
    c.Write([]byte{5, 2})
    
    n, err = c.Read(buf)
    if err != nil || n < 2 {
        return err
    }
    if buf[0] != 1 {
        return fmt.Errorf("auth ver")
    }
    ulen := int(buf[1])
    if n < 2+ulen+1 {
        return fmt.Errorf("auth data")
    }
    user := string(buf[2 : 2+ulen])
    plen := int(buf[2+ulen])
    if n < 2+ulen+1+plen {
        return fmt.Errorf("pass data")
    }
    pass := string(buf[3+ulen : 3+ulen+plen])
    
    if user != cfg.Username || pass != cfg.Password {
        c.Write([]byte{1, 1})
        return fmt.Errorf("auth")
    }
    c.Write([]byte{1, 0})
    
    n, err = c.Read(buf)
    if err != nil || n < 4 {
        return err
    }
    if buf[1] != 1 {
        c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
        return fmt.Errorf("cmd")
    }
    
    var host string
    var port uint16
    
    switch buf[3] {
    case 1:
        if n < 10 {
            return fmt.Errorf("ipv4")
        }
        host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
        port = binary.BigEndian.Uint16(buf[8:10])
    case 3:
        dlen := int(buf[4])
        if n < 5+dlen+2 {
            return fmt.Errorf("domain")
        }
        host = string(buf[5 : 5+dlen])
        port = binary.BigEndian.Uint16(buf[5+dlen : 7+dlen])
    default:
        c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
        return fmt.Errorf("atyp")
    }
    
    return connectAndForward(c, host, port, ipv6, true)
}

func handleHTTP(c net.Conn, fb byte, ipv6 string) error {
    defer releaseIPv6(ipv6)
    r := bufio.NewReader(io.MultiReader(strings.NewReader(string(fb)), c))
    line, _ := r.ReadString('\n')
    parts := strings.Fields(line)
    if len(parts) < 2 {
        return fmt.Errorf("invalid")
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
        return fmt.Errorf("auth")
    }
    if parts[0] != "CONNECT" {
        c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
        return fmt.Errorf("method")
    }
    hp := strings.Split(parts[1], ":")
    if len(hp) < 2 {
        return fmt.Errorf("invalid host:port format")
    }
    var port uint16
    fmt.Sscanf(hp[1], "%d", &port)
    return connectAndForward(c, hp[0], port, ipv6, false)
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
    ipv6 := acquireIPv6()
    fb := make([]byte, 1)
    if _, err := c.Read(fb); err != nil {
        releaseIPv6(ipv6)
        return
    }
    if fb[0] == 0x05 {
        handleSOCKS5(c, ipv6)
    } else {
        handleHTTP(c, fb[0], ipv6)
    }
}

func statsRoutine() {
    t := time.NewTicker(30 * time.Second)
    defer t.Stop()
    for range t.C {
        ipCount := 0
        totalIPConns := 0
        ipConcurrency.Range(func(key, value interface{}) bool {
            count := atomic.LoadInt32(value.(*int32))
            if count > 0 {
                ipCount++
                totalIPConns += int(count)
            }
            return true
        })
        log.Printf("[Stats] Conn: A=%d T=%d S=%d F=%d | IPv6: IPs=%d Conns=%d Retries=%d | Traffic: In=%.1fM Out=%.1fM",
            atomic.LoadInt64(&activeConns), atomic.LoadInt64(&totalConns),
            atomic.LoadInt64(&successConns), atomic.LoadInt64(&failedConns),
            ipCount, totalIPConns, atomic.LoadInt64(&ipRetries),
            float64(atomic.LoadInt64(&bytesIn))/1e6, float64(atomic.LoadInt64(&bytesOut))/1e6)
    }
}

func metricsServer() {
    mux := http.NewServeMux()
    mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
        ipCount := 0
        ipConcurrency.Range(func(key, value interface{}) bool {
            if atomic.LoadInt32(value.(*int32)) > 0 {
                ipCount++
            }
            return true
        })
        fmt.Fprintf(w, "proxy_active %d\nproxy_total %d\nproxy_success %d\nproxy_failed %d\nipv6_using %d\nipv6_retries %d\n",
            atomic.LoadInt64(&activeConns), atomic.LoadInt64(&totalConns),
            atomic.LoadInt64(&successConns), atomic.LoadInt64(&failedConns),
            ipCount, atomic.LoadInt64(&ipRetries))
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
    log.Printf("IPv6 Rotating Proxy | Port:%s Metrics:%s IPv6:%v MaxPerIP:%d", 
        cfg.ProxyPort, cfg.MetricsPort, cfg.IPv6Enabled, cfg.MaxPerIP)
    go statsRoutine()
    go metricsServer()
    ln, _ := net.Listen("tcp", ":"+cfg.ProxyPort)
    defer ln.Close()
    for {
        conn, _ := ln.Accept()
        go handleConn(conn)
    }
}
GOCODE

print_success "源代码创建完成"

# 编译
print_info "编译 Go 程序..."
go mod init ipv6-proxy >/dev/null 2>&1
go build -ldflags="-s -w" -o ipv6-proxy main.go
print_success "编译完成: /opt/ipv6-proxy/ipv6-proxy"

# systemd
print_info "创建 systemd 服务..."
cat > /etc/systemd/system/ipv6-proxy.service << 'SERVICE'
[Unit]
Description=IPv6 Rotating Proxy
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
print_success "服务文件创建完成"

# 启动
print_info "启动服务..."
systemctl daemon-reload
systemctl enable ipv6-proxy
systemctl start ipv6-proxy
print_success "服务已启动"

sleep 3

# 完成
echo ""
echo "========================================="
print_success "安装完成！"
echo "========================================="
echo ""
echo "📍 代理地址: $IPV4:$PROXY_PORT"
echo "👤 用户名: $USERNAME"
echo "🔑 密码: $PASSWORD"
echo "📊 每IP并发: $MAX_PER_IP"
$USE_IPV6 && echo "🌐 IPv6池: $IPV6_PREFIX::/64" || echo "⚠️  IPv6: 禁用"
echo ""
echo "🧪 测试命令:"
echo "  curl -x socks5h://$USERNAME:$PASSWORD@$IPV4:$PROXY_PORT http://ip.sb"
echo "  curl -x http://$USERNAME:$PASSWORD@$IPV4:$PROXY_PORT http://ip.sb"
echo ""
echo "📊 监控命令:"
echo "  curl http://localhost:$METRICS_PORT/metrics"
echo "  curl http://localhost:$METRICS_PORT/health"
echo ""
echo "📝 日志命令:"
echo "  journalctl -u ipv6-proxy -f"
echo "  systemctl status ipv6-proxy"
echo ""

print_info "服务状态:"
systemctl status ipv6-proxy --no-pager -l | head -12
