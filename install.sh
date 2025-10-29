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
echo "  IPv6 Rotating Proxy - SOCKS5 修复版"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    print_error "请使用 root 权限运行"
    exit 1
fi

print_info "停止现有服务..."
systemctl stop ipv6-proxy 2>/dev/null || true

print_info "更新代理程序..."
export PATH=$PATH:/usr/local/go/bin
cd /opt/ipv6-proxy

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
    
    // 读取：[VER, NMETHODS, METHODS...]
    n, err := c.Read(buf)
    if err != nil || n < 2 {
        return fmt.Errorf("read greeting failed")
    }
    if buf[0] != 5 {
        return fmt.Errorf("unsupported version")
    }
    
    // 回复：选择用户名密码认证
    c.Write([]byte{5, 2})
    
    // 读取认证请求：[VER=1, ULEN, USER..., PLEN, PASS...]
    n, err = c.Read(buf)
    if err != nil || n < 2 {
        return fmt.Errorf("read auth failed")
    }
    if buf[0] != 1 {
        return fmt.Errorf("invalid auth version")
    }
    
    ulen := int(buf[1])
    if n < 2+ulen+1 {
        return fmt.Errorf("incomplete auth data")
    }
    user := string(buf[2 : 2+ulen])
    plen := int(buf[2+ulen])
    if n < 2+ulen+1+plen {
        return fmt.Errorf("incomplete password")
    }
    pass := string(buf[3+ulen : 3+ulen+plen])
    
    if user != cfg.Username || pass != cfg.Password {
        c.Write([]byte{1, 1})
        return fmt.Errorf("auth failed")
    }
    c.Write([]byte{1, 0})
    
    // 读取请求：[VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
    n, err = c.Read(buf)
    if err != nil || n < 4 {
        return fmt.Errorf("read request failed")
    }
    if buf[1] != 1 {
        c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
        return fmt.Errorf("only CONNECT supported")
    }
    
    var host string
    var port uint16
    atyp := buf[3]
    
    switch atyp {
    case 1: // IPv4
        if n < 10 {
            return fmt.Errorf("incomplete IPv4")
        }
        host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
        port = binary.BigEndian.Uint16(buf[8:10])
    case 3: // Domain
        dlen := int(buf[4])
        if n < 5+dlen+2 {
            return fmt.Errorf("incomplete domain")
        }
        host = string(buf[5 : 5+dlen])
        port = binary.BigEndian.Uint16(buf[5+dlen : 7+dlen])
    case 4: // IPv6
        if n < 22 {
            return fmt.Errorf("incomplete IPv6")
        }
        host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
            binary.BigEndian.Uint16(buf[4:6]), binary.BigEndian.Uint16(buf[6:8]),
            binary.BigEndian.Uint16(buf[8:10]), binary.BigEndian.Uint16(buf[10:12]),
            binary.BigEndian.Uint16(buf[12:14]), binary.BigEndian.Uint16(buf[14:16]),
            binary.BigEndian.Uint16(buf[16:18]), binary.BigEndian.Uint16(buf[18:20]))
        port = binary.BigEndian.Uint16(buf[20:22])
    default:
        c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
        return fmt.Errorf("unsupported address type")
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
        return fmt.Errorf("invalid host:port")
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

print_info "重新编译..."
go build -ldflags="-s -w" -o ipv6-proxy main.go

print_info "启动服务..."
systemctl start ipv6-proxy

sleep 2

print_success "完成！测试命令："
echo "curl -x socks5h://proxy:proxy@38.92.26.36:20000 http://ip.sb"
