#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

clear
echo ""
echo "========================================="
echo "  IPv6 Rotating Proxy - SOCKS5 修复"
echo "========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    print_error "请使用 root 权限运行"
    exit 1
fi

# 读取配置
if [ ! -f /etc/ipv6-proxy/config.txt ]; then
    print_error "配置文件不存在，请先运行安装脚本"
    exit 1
fi

source /etc/ipv6-proxy/config.txt

print_info "当前配置："
echo "  端口: $START_PORT-$((START_PORT + PORT_COUNT - 1))"
echo "  用户: $USERNAME"
echo ""

# 停止服务
print_info "停止服务..."
systemctl stop ipv6-proxy 2>/dev/null || true
pkill -9 -f "ipv6-proxy" 2>/dev/null || true
sleep 2

# 生成修复后的代码
print_info "生成修复代码..."
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
			
			if conn, ok := dst.(net.Conn); ok {
				conn.SetDeadline(time.Now().Add(5 * time.Minute))
			}
			if conn, ok := src.(net.Conn); ok {
				conn.SetDeadline(time.Now().Add(5 * time.Minute))
			}
		}
		if err != nil {
			return
		}
	}
}

func handleSOCKS5(c net.Conn, ipv6 string) error {
	buf := make([]byte, 512)
	
	// 步骤1: 读取客户端支持的认证方法
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 5 {
		return fmt.Errorf("invalid socks version")
	}
	
	nMethods := int(buf[1])
	if _, err := io.ReadFull(c, buf[:nMethods]); err != nil {
		return err
	}
	
	// 步骤2: 服务端选择用户名密码认证方法(0x02)
	c.Write([]byte{5, 2})
	
	// 步骤3: 读取用户名密码认证请求
	// 格式: [认证版本(1字节), 用户名长度(1字节), 用户名, 密码长度(1字节), 密码]
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 1 {
		return fmt.Errorf("invalid auth version")
	}
	
	// 读取用户名
	userLen := int(buf[1])
	if _, err := io.ReadFull(c, buf[:userLen]); err != nil {
		return err
	}
	user := string(buf[:userLen])
	
	// 读取密码
	if _, err := io.ReadFull(c, buf[:1]); err != nil {
		return err
	}
	passLen := int(buf[0])
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
	
	// 步骤4: 读取连接请求
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return err
	}
	
	var host string
	var port uint16
	
	if buf[3] == 1 {
		if _, err := io.ReadFull(c, buf[:6]); err != nil {
			return err
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		port = binary.BigEndian.Uint16(buf[4:6])
	} else if buf[3] == 3 {
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return err
		}
		dlen := int(buf[0])
		if _, err := io.ReadFull(c, buf[:dlen+2]); err != nil {
			return err
		}
		host = string(buf[:dlen])
		port = binary.BigEndian.Uint16(buf[dlen : dlen+2])
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
	d.Timeout = 30 * time.Second
	
	var remote net.Conn
	var err error
	maxRetries := 3
	
	for retry := 0; retry < maxRetries; retry++ {
		remote, err = d.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err == nil {
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
	
	c.SetDeadline(time.Now().Add(5 * time.Minute))
	remote.SetDeadline(time.Now().Add(5 * time.Minute))
	
	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(remote, c, "up", &wg)
	go transfer(c, remote, "down", &wg)
	wg.Wait()
	return nil
}

func handleConn(c net.Conn) {
	atomic.AddInt64(&activeConns, 1)
	atomic.AddInt64(&totalConns, 1)
	
	defer func() {
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
		log.Printf("[统计] 活跃:%d 总计:%d 成功:%d 失败:%d 入站:%.2fGB 出站:%.2fGB",
			atomic.LoadInt64(&activeConns), atomic.LoadInt64(&totalConns),
			atomic.LoadInt64(&successConns), atomic.LoadInt64(&failedConns),
			float64(atomic.LoadInt64(&bytesIn))/1e9, float64(atomic.LoadInt64(&bytesOut))/1e9)
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
	http.ListenAndServe(":"+cfg.MetricsPort, mux)
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
	log.Printf("IPv6 Rotating Proxy | 端口: %d-%d (%d个) | IPv6: %v", startPort, endPort, portCount, cfg.IPv6Enabled)
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
	
	log.Printf("服务运行中,按 Ctrl+C 或发送 SIGTERM 优雅关闭...")
	<-sigChan
	
	log.Printf("收到关闭信号,开始优雅关闭...")
	log.Printf("当前活跃连接: %d", atomic.LoadInt64(&activeConns))
	
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

print_info "编译..."
go mod init ipv6-proxy >/dev/null 2>&1 || true
go build -ldflags="-s -w" -o ipv6-proxy main.go

if [ $? -ne 0 ]; then
    print_error "编译失败"
    exit 1
fi

print_success "编译成功"

# 启动服务
print_info "启动服务..."
systemctl daemon-reload
systemctl start ipv6-proxy

sleep 3

if systemctl is-active --quiet ipv6-proxy; then
    print_success "服务已启动"
    echo ""
    echo "========================================="
    echo "  修复完成"
    echo "========================================="
    echo ""
    echo "修复内容:"
    echo "  ✓ SOCKS5 认证协议解析错误"
    echo ""
    echo "未修改:"
    echo "  • IPv6 轮换逻辑 (保持原样)"
    echo "  • 超时机制 (保持原样)"
    echo "  • 其他所有代码 (保持原样)"
    echo ""
    echo "测试命令:"
    echo "  HTTP:   curl -x http://$USERNAME:$PASSWORD@127.0.0.1:$START_PORT http://ip.sb"
    echo "  SOCKS5: curl -x socks5://$USERNAME:$PASSWORD@127.0.0.1:$START_PORT http://ip.sb"
    echo ""
else
    print_error "服务启动失败"
    echo ""
    echo "查看日志:"
    journalctl -u ipv6-proxy -n 30
    exit 1
fi
