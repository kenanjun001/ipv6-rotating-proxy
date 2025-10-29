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
echo "  IPv6 随机代理池"
echo "  随机抽取 + 并发检查"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    print_error "请使用 root 权限运行"
    exit 1
fi

# ==================== 清理 ====================
print_info "第 1 步：检查现有服务和进程..."
echo ""

# 检查服务
print_info "检查 systemd 服务："
if systemctl list-units --type=service --all | grep -q "ipv6-proxy"; then
    systemctl status ipv6-proxy --no-pager 2>/dev/null | head -3 || true
else
    echo "  无 ipv6-proxy 服务"
fi

# 检查进程
print_info "检查运行的进程："
if pgrep -f "ipv6-proxy" >/dev/null; then
    ps aux | grep -E "ipv6-proxy" | grep -v grep
else
    echo "  无相关进程"
fi

# 检查端口
print_info "检查端口占用："
for port in 20000 20001; do
    if lsof -i :$port >/dev/null 2>&1; then
        echo "  $port: $(lsof -ti :$port 2>/dev/null | wc -l) 个进程占用"
    else
        echo "  $port: 空闲"
    fi
done

echo ""
read -p "是否清理? [Y/n] " do_clean
if [[ $do_clean =~ ^[Nn]$ ]]; then
    print_warning "跳过清理"
else
    print_info "开始清理..."
    
    # 停止服务
    for service in ipv6-proxy go-proxy dynamic-proxy python-proxy; do
        if systemctl list-unit-files | grep -q "^$service.service"; then
            systemctl stop $service 2>/dev/null && print_success "停止服务: $service" || true
            systemctl disable $service 2>/dev/null && print_success "禁用服务: $service" || true
            rm -f /etc/systemd/system/$service.service && print_success "删除服务文件: $service" || true
        fi
    done
    
    # 杀进程
    print_info "终止进程..."
    if pkill -9 -f "ipv6-proxy" 2>/dev/null; then
        print_success "已终止 ipv6-proxy 进程"
    fi
    if pkill -9 -f "proxy-server" 2>/dev/null; then
        print_success "已终止 proxy-server 进程"
    fi
    
    # 释放端口
    print_info "释放端口..."
    for port in 20000 20001; do
        if lsof -ti :$port >/dev/null 2>&1; then
            fuser -k $port/tcp 2>/dev/null && print_success "释放端口: $port" || true
        fi
    done
    
    systemctl daemon-reload
    sleep 2
    
    # 验证
    print_info "验证清理结果..."
    if pgrep -f "ipv6-proxy" >/dev/null || lsof -i :20000 >/dev/null 2>&1 || lsof -i :20001 >/dev/null 2>&1; then
        print_warning "仍有残留，再次强制清理..."
        pkill -9 -f "proxy" 2>/dev/null || true
        fuser -k -9 20000/tcp 2>/dev/null || true
        fuser -k -9 20001/tcp 2>/dev/null || true
        sleep 2
    fi
    
    # 最终检查
    if pgrep -f "ipv6-proxy" >/dev/null || lsof -i :20000 >/dev/null 2>&1; then
        print_error "清理失败！请手动清理后重试"
        echo ""
        echo "手动清理命令："
        echo "  pkill -9 -f ipv6-proxy"
        echo "  fuser -k -9 20000/tcp"
        echo "  systemctl stop ipv6-proxy"
        exit 1
    else
        print_success "清理完成！"
    fi
fi

echo ""

# ==================== 配置 ====================
print_info "配置参数..."
echo ""

IPV4=$(curl -s -4 --max-time 3 ifconfig.me 2>/dev/null || echo "")
if [ -z "$IPV4" ]; then
    read -p "IPv4: " IPV4
else
    print_success "检测到 IPv4: $IPV4"
fi

if ping6 -c 1 -W 2 2001:4860:4860::8888 &>/dev/null; then
    IPV6_ADDR=$(ip -6 addr show scope global 2>/dev/null | grep inet6 | head -1 | awk '{print $2}' | cut -d'/' -f1)
    if [ -n "$IPV6_ADDR" ]; then
        IPV6_PREFIX=$(echo "$IPV6_ADDR" | cut -d':' -f1-4)
        print_success "检测到 IPv6: $IPV6_PREFIX::/64"
        USE_IPV6=true
    else
        USE_IPV6=false
    fi
else
    USE_IPV6=false
    IPV6_PREFIX=""
fi

read -p "代理端口 [20000]: " PROXY_PORT
PROXY_PORT=${PROXY_PORT:-20000}
read -p "监控端口 [20001]: " METRICS_PORT
METRICS_PORT=${METRICS_PORT:-20001}
read -p "每IP最大并发 [5]: " MAX_PER_IP
MAX_PER_IP=${MAX_PER_IP:-5}
read -p "用户名 [proxy]: " USERNAME
USERNAME=${USERNAME:-proxy}
read -sp "密码 [自动生成]: " PASSWORD
echo ""
[ -z "$PASSWORD" ] && PASSWORD=$(openssl rand -hex 6) && print_info "密码: $PASSWORD"

echo ""
echo "========================================="
echo "服务器: $IPV4:$PROXY_PORT"
echo "用户: $USERNAME / $PASSWORD"
echo "每IP并发: $MAX_PER_IP"
$USE_IPV6 && echo "IPv6: $IPV6_PREFIX::/64"
echo "========================================="
echo ""
read -p "确认? [Y/n] " confirm
[[ $confirm =~ ^[Nn]$ ]] && exit 0

# ==================== 系统优化 ====================
print_info "系统优化..."

cat >> /etc/sysctl.conf << 'EOF'

# IPv6 Proxy
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_tw_buckets = 2000000
fs.file-max = 2097152
EOF

sysctl -p >/dev/null 2>&1

cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
EOF

# ==================== 安装 ====================
print_info "安装..."

export PATH=$PATH:/usr/local/go/bin
if ! command -v go &> /dev/null; then
    print_info "安装 Go..."
    cd /tmp
    wget -q --show-progress https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
fi

rm -rf /opt/ipv6-proxy
mkdir -p /opt/ipv6-proxy /etc/ipv6-proxy
cd /opt/ipv6-proxy

cat > /etc/ipv6-proxy/config.txt << CONFIG
PROXY_PORT=$PROXY_PORT
METRICS_PORT=$METRICS_PORT
USERNAME=$USERNAME
PASSWORD=$PASSWORD
IPV6_ENABLED=$USE_IPV6
IPV6_PREFIX=$IPV6_PREFIX
MAX_PER_IP=$MAX_PER_IP
CONFIG

print_info "创建代理程序..."

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
    cfg        Config
    ipConcurrency sync.Map  // map[string]*int32 记录每个IP的并发数
    stats      Stats
    bufferPool = sync.Pool{New: func() interface{} { return make([]byte, 32768) }}
    authToken  string
)

type Config struct {
    ProxyPort, MetricsPort, Username, Password, IPv6Prefix string
    IPv6Enabled                                            bool
    MaxPerIP                                               int
}

type Stats struct {
    active, total, success, failed int64
    bytesIn, bytesOut              int64
    ipRetries                      int64  // IP重试次数
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
    authToken = base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
}

// 随机生成IPv6
func randomIPv6() string {
    if !cfg.IPv6Enabled || cfg.IPv6Prefix == "" {
        return ""
    }
    return fmt.Sprintf("%s:%x:%x:%x:%x", cfg.IPv6Prefix,
        rand.Intn(0x10000), rand.Intn(0x10000),
        rand.Intn(0x10000), rand.Intn(0x10000))
}

// 获取可用的IPv6（带并发检查和重试）
func acquireIPv6() string {
    if !cfg.IPv6Enabled {
        return ""
    }
    
    maxRetries := 100  // 最多重试100次
    for i := 0; i < maxRetries; i++ {
        ip := randomIPv6()
        
        // 获取或创建该IP的并发计数器
        val, _ := ipConcurrency.LoadOrStore(ip, new(int32))
        counter := val.(*int32)
        
        // 尝试增加并发数
        current := atomic.LoadInt32(counter)
        if current < int32(cfg.MaxPerIP) {
            // 并发数未满，可以使用
            atomic.AddInt32(counter, 1)
            if i > 0 {
                atomic.AddInt64(&stats.ipRetries, int64(i))
            }
            return ip
        }
        
        // 该IP已满，继续随机抽取下一个
        if i > 0 && i%10 == 0 {
            log.Printf("[Warn] IP池繁忙，已重试 %d 次", i)
        }
    }
    
    // 100次都没找到，直接返回一个随机IP（降级策略）
    log.Printf("[Warn] 重试次数过多，使用降级策略")
    return randomIPv6()
}

// 释放IPv6
func releaseIPv6(ip string) {
    if ip == "" {
        return
    }
    if val, ok := ipConcurrency.Load(ip); ok {
        counter := val.(*int32)
        atomic.AddInt32(counter, -1)
    }
}

func checkAuth(header string) bool {
    for _, line := range strings.Split(header, "\r\n") {
        if strings.HasPrefix(strings.ToLower(line), "proxy-authorization: basic ") {
            return strings.TrimSpace(line[27:]) == authToken
        }
    }
    return false
}

func transfer(dst io.Writer, src io.Reader, dir string, wg *sync.WaitGroup) {
    defer wg.Done()
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    n, _ := io.CopyBuffer(dst, src, buf)
    if dir == "out" {
        atomic.AddInt64(&stats.bytesOut, n)
    } else {
        atomic.AddInt64(&stats.bytesIn, n)
    }
}

func handleSOCKS5(client net.Conn, ipv6 string) error {
    defer releaseIPv6(ipv6)
    
    buf := make([]byte, 512)
    io.ReadFull(client, buf[:2])
    nMethods := int(buf[1])
    io.ReadFull(client, buf[:nMethods])
    client.Write([]byte{5, 2})
    
    io.ReadFull(client, buf[:2])
    uLen := int(buf[1])
    io.ReadFull(client, buf[:uLen])
    user := string(buf[:uLen])
    io.ReadFull(client, buf[:1])
    pLen := int(buf[0])
    io.ReadFull(client, buf[:pLen])
    pass := string(buf[:pLen])
    
    if user != cfg.Username || pass != cfg.Password {
        client.Write([]byte{1, 1})
        return fmt.Errorf("auth")
    }
    client.Write([]byte{1, 0})
    
    io.ReadFull(client, buf[:4])
    var host string
    var port uint16
    
    if buf[3] == 1 {
        io.ReadFull(client, buf[:6])
        host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
        port = binary.BigEndian.Uint16(buf[4:6])
    } else if buf[3] == 3 {
        io.ReadFull(client, buf[:1])
        dLen := int(buf[0])
        io.ReadFull(client, buf[:dLen+2])
        host = string(buf[:dLen])
        port = binary.BigEndian.Uint16(buf[dLen : dLen+2])
    } else {
        client.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
        return fmt.Errorf("unsupported")
    }
    
    return dial(client, host, port, ipv6, true)
}

func handleHTTP(client net.Conn, firstByte byte, ipv6 string) error {
    defer releaseIPv6(ipv6)
    
    reader := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), client))
    line, _ := reader.ReadString('\n')
    parts := strings.Fields(line)
    if len(parts) < 2 {
        return fmt.Errorf("invalid")
    }
    
    var header strings.Builder
    for {
        l, _ := reader.ReadString('\n')
        header.WriteString(l)
        if l == "\r\n" || l == "\n" {
            break
        }
    }
    
    if !checkAuth(header.String()) {
        client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
        return fmt.Errorf("auth")
    }
    
    if parts[0] != "CONNECT" {
        client.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
        return fmt.Errorf("method")
    }
    
    hostPort := strings.Split(parts[1], ":")
    if len(hostPort) != 2 {
        return fmt.Errorf("invalid host:port")
    }
    
    var port uint16
    fmt.Sscanf(hostPort[1], "%d", &port)
    return dial(client, hostPort[0], port, ipv6, false)
}

func dial(client net.Conn, host string, port uint16, ipv6 string, socks bool) error {
    var dialer net.Dialer
    dialer.Timeout = 10 * time.Second
    
    if ipv6 != "" {
        if addr, err := net.ResolveIPAddr("ip6", ipv6); err == nil {
            dialer.LocalAddr = &net.TCPAddr{IP: addr.IP}
        }
    }
    
    remote, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
    if err != nil {
        atomic.AddInt64(&stats.failed, 1)
        if socks {
            client.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
        } else {
            client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
        }
        return err
    }
    defer remote.Close()
    
    if tcp, ok := remote.(*net.TCPConn); ok {
        tcp.SetNoDelay(true)
    }
    
    atomic.AddInt64(&stats.success, 1)
    
    if socks {
        client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
    } else {
        client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
    }
    
    var wg sync.WaitGroup
    wg.Add(2)
    go transfer(remote, client, "out", &wg)
    go transfer(client, remote, "in", &wg)
    wg.Wait()
    
    return nil
}

func handleConn(conn net.Conn) {
    defer conn.Close()
    defer atomic.AddInt64(&stats.active, -1)
    
    atomic.AddInt64(&stats.active, 1)
    atomic.AddInt64(&stats.total, 1)
    
    // 获取可用的IPv6（带并发检查）
    ipv6 := acquireIPv6()
    
    firstByte := make([]byte, 1)
    if _, err := conn.Read(firstByte); err != nil {
        releaseIPv6(ipv6)
        return
    }
    
    if firstByte[0] == 0x05 {
        handleSOCKS5(conn, ipv6)
    } else {
        handleHTTP(conn, firstByte[0], ipv6)
    }
}

func statsLogger() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    var lastTotal, lastSuccess int64
    lastTime := time.Now()
    
    for range ticker.C {
        now := time.Now()
        elapsed := now.Sub(lastTime).Seconds()
        
        total := atomic.LoadInt64(&stats.total)
        success := atomic.LoadInt64(&stats.success)
        retries := atomic.LoadInt64(&stats.ipRetries)
        
        qps := float64(total-lastTotal) / elapsed
        
        // 统计当前使用的IP数
        ipCount := 0
        totalConcurrent := 0
        ipConcurrency.Range(func(key, value interface{}) bool {
            count := atomic.LoadInt32(value.(*int32))
            if count > 0 {
                ipCount++
                totalConcurrent += int(count)
            }
            return true
        })
        
        log.Printf("[Stats] Active=%d QPS=%.0f Success=%d Failed=%d | IPv6: Using=%d Conns=%d Retries=%d | Traffic: ↓%.1fGB ↑%.1fGB",
            atomic.LoadInt64(&stats.active), qps,
            success, atomic.LoadInt64(&stats.failed),
            ipCount, totalConcurrent, retries,
            float64(atomic.LoadInt64(&stats.bytesIn))/1e9,
            float64(atomic.LoadInt64(&stats.bytesOut))/1e9)
        
        lastTotal = total
        lastSuccess = success
        lastTime = now
    }
}

func metricsServer() {
    mux := http.NewServeMux()
    
    mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
        ipCount := 0
        totalConcurrent := 0
        ipConcurrency.Range(func(key, value interface{}) bool {
            count := atomic.LoadInt32(value.(*int32))
            if count > 0 {
                ipCount++
                totalConcurrent += int(count)
            }
            return true
        })
        
        fmt.Fprintf(w, "proxy_active %d\n", atomic.LoadInt64(&stats.active))
        fmt.Fprintf(w, "proxy_total %d\n", atomic.LoadInt64(&stats.total))
        fmt.Fprintf(w, "proxy_success %d\n", atomic.LoadInt64(&stats.success))
        fmt.Fprintf(w, "proxy_failed %d\n", atomic.LoadInt64(&stats.failed))
        fmt.Fprintf(w, "ipv6_using %d\n", ipCount)
        fmt.Fprintf(w, "ipv6_connections %d\n", totalConcurrent)
        fmt.Fprintf(w, "ipv6_retries %d\n", atomic.LoadInt64(&stats.ipRetries))
    })
    
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "OK")
    })
    
    mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
        ipCount := 0
        totalConcurrent := 0
        ipDetails := make(map[string]int)
        
        ipConcurrency.Range(func(key, value interface{}) bool {
            count := atomic.LoadInt32(value.(*int32))
            if count > 0 {
                ipCount++
                totalConcurrent += int(count)
                ipDetails[key.(string)] = int(count)
            }
            return true
        })
        
        total := atomic.LoadInt64(&stats.total)
        success := atomic.LoadInt64(&stats.success)
        var successRate float64
        if total > 0 {
            successRate = float64(success) * 100 / float64(total)
        }
        
        fmt.Fprintf(w, "IPv6 Random Proxy with Concurrency Control\n")
        fmt.Fprintf(w, "==========================================\n")
        fmt.Fprintf(w, "Active Connections: %d\n", atomic.LoadInt64(&stats.active))
        fmt.Fprintf(w, "Total: %d\n", total)
        fmt.Fprintf(w, "Success: %d (%.1f%%)\n", success, successRate)
        fmt.Fprintf(w, "Failed: %d\n", atomic.LoadInt64(&stats.failed))
        fmt.Fprintf(w, "\nIPv6 Pool:\n")
        fmt.Fprintf(w, "  Using IPs: %d\n", ipCount)
        fmt.Fprintf(w, "  Total Connections: %d\n", totalConcurrent)
        fmt.Fprintf(w, "  Max per IP: %d\n", cfg.MaxPerIP)
        fmt.Fprintf(w, "  Retries: %d\n", atomic.LoadInt64(&stats.ipRetries))
        fmt.Fprintf(w, "\nTraffic:\n")
        fmt.Fprintf(w, "  In: %.2f GB\n", float64(atomic.LoadInt64(&stats.bytesIn))/1e9)
        fmt.Fprintf(w, "  Out: %.2f GB\n", float64(atomic.LoadInt64(&stats.bytesOut))/1e9)
        
        if len(ipDetails) > 0 && len(ipDetails) <= 20 {
            fmt.Fprintf(w, "\nActive IPs (top 20):\n")
            for ip, count := range ipDetails {
                fmt.Fprintf(w, "  %s: %d/%d\n", ip, count, cfg.MaxPerIP)
            }
        }
    })
    
    http.ListenAndServe(":"+cfg.MetricsPort, mux)
}

func main() {
    loadConfig()
    rand.Seed(time.Now().UnixNano())
    runtime.GOMAXPROCS(runtime.NumCPU())
    
    log.Printf("IPv6 Random Proxy with Concurrency Control")
    log.Printf("  Port: %s", cfg.ProxyPort)
    log.Printf("  Metrics: %s", cfg.MetricsPort)
    log.Printf("  IPv6: %v", cfg.IPv6Enabled)
    log.Printf("  Max per IP: %d", cfg.MaxPerIP)
    log.Printf("  Mode: Random pick with retry")
    
    go statsLogger()
    go metricsServer()
    
    listener, err := net.Listen("tcp", ":"+cfg.ProxyPort)
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()
    
    log.Printf("Listening on :%s", cfg.ProxyPort)
    
    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        go handleConn(conn)
    }
}
GOCODE

print_info "编译..."
go mod init ipv6-proxy >/dev/null 2>&1
go build -ldflags="-s -w" -o ipv6-proxy main.go
print_success "编译完成"

cat > /etc/systemd/system/ipv6-proxy.service << 'SERVICE'
[Unit]
Description=IPv6 Random Proxy with Concurrency Control
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ipv6-proxy
ExecStart=/opt/ipv6-proxy/ipv6-proxy
Restart=always
RestartSec=3
LimitNOFILE=2097152

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable ipv6-proxy
systemctl start ipv6-proxy
sleep 3

echo ""
echo "========================================="
print_success "安装完成！"
echo "========================================="
echo ""
echo "📍 代理: $IPV4:$PROXY_PORT"
echo "👤 用户: $USERNAME"
echo "🔑 密码: $PASSWORD"
echo "🎲 模式: 随机抽取 + 并发检查"
echo "📊 每IP限制: $MAX_PER_IP 并发"
$USE_IPV6 && echo "🌐 IPv6: $IPV6_PREFIX::/64"
echo ""
echo "📊 监控:"
echo "  curl http://localhost:$METRICS_PORT/stats"
echo ""
echo "🧪 测试:"
echo "  curl -x http://$USERNAME:$PASSWORD@$IPV4:$PROXY_PORT http://ipv6.ip.sb"
echo ""
echo "📝 日志:"
echo "  journalctl -u ipv6-proxy -f"
echo ""

systemctl status ipv6-proxy --no-pager | head -15
