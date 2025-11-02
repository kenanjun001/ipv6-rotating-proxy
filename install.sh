#!/bin/bash
#
# IPv6 代理 v7.5 优化版 一键安装脚本
#
# 特性：
# ✅ 统一卡片式界面
# ✅ 一键操作设计
# ✅ 多端口支持
# ✅ 多代理管理
# ✅ 自清理功能
#

INSTALL_DIR="/opt/ipv6-proxy"
BUILD_DIR="/root/ipv6-proxy-build"
GO_VERSION="1.21.5"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=/usr/local/go/bin:$PATH:$GOPATH/bin

set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "❌ 错误：需要 root 权限"
  exit 1
fi

echo "============================================="
echo "=== IPv6 代理 v7.5 优化版 安装中 ==="
echo "============================================="
echo ""

# --- 清理 ---
echo "--- 步骤 1: 清理旧版本 ---"
systemctl stop ipv6-proxy.service >/dev/null 2>&1 || true
systemctl disable ipv6-proxy.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/ipv6-proxy.service
rm -rf /opt/ipv6-proxy
rm -rf "$BUILD_DIR"
systemctl daemon-reload
echo "✅ 清理完成"
echo ""

# --- 安装依赖 ---
echo "--- 步骤 2: 安装依赖 ---"
apt-get update >/dev/null
apt-get install -y wget >/dev/null
apt-get remove -y golang-go >/dev/null 2>&1 || true

if [ ! -d "/usr/local/go" ] || ! /usr/local/go/bin/go version | grep -q "$GO_VERSION"; then
  echo "下载 Go $GO_VERSION..."
  wget -q "$GO_URL" -O "/tmp/$GO_TAR"
  tar -C /usr/local -xzf "/tmp/$GO_TAR"
  rm "/tmp/$GO_TAR"
fi

echo "✅ Go 环境就绪"
echo ""

# --- 创建源代码 ---
echo "--- 步骤 3: 创建源代码 ---"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cat << 'GOEOF' > main.go
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/vishvananda/netlink"
	"golang.org/x/term"
)

var (
	config            Config
	stats             Stats
	
	ipv6Pool      []net.IP
	ipv6PoolIndex map[string]int
	
	poolLock          sync.RWMutex
	backgroundRunning int32
	backgroundAdded   int64
	connLogs          []*ConnLog
	connLogsLock      sync.RWMutex
	failLogs          []*ConnLog
	failLogsLock      sync.RWMutex
	maxLogs           = 100

	activeConnections     = make(map[string]*ActiveConn)
	activeConnectionsLock sync.RWMutex

	statsHistory     []*StatsSnapshot
	statsHistoryLock sync.RWMutex
	maxHistory       = 60

	autoRotateEnabled  int32
	autoRotateInterval int64
	nextRotateTime     time.Time
	nextRotateTimeLock sync.RWMutex

	discardQueue chan net.IP
	rng          = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	rngLock      sync.Mutex

	iface     netlink.Link
	prefixIP  net.IP
	prefixNet *net.IPNet

	configFilePath string
	indexHTMLPath  string
	
	// 多端口和多代理支持
	proxyPorts     []ProxyPort
	proxyPortsLock sync.RWMutex
	proxyAccounts  []ProxyAccount
	accountsLock   sync.RWMutex
)

type Config struct {
	Port              string `json:"port"`
	WebPort           string `json:"web_port"`
	WebUsername       string `json:"web_username"`
	WebPassword       string `json:"web_password"`
	Username          string `json:"username"`
	Password          string `json:"password"`
	IPv6Prefix        string `json:"ipv6_prefix"`
	Interface         string `json:"interface"`
	InitialPool       int    `json:"initial_pool"`
	TargetPool        int    `json:"target_pool"`
	AutoRotate        bool   `json:"auto_rotate"`
	AutoRotateHours   int    `json:"auto_rotate_hours"`
	AutoClean         bool   `json:"auto_clean"`
	ProxyPorts        []ProxyPort    `json:"proxy_ports"`
	ProxyAccounts     []ProxyAccount `json:"proxy_accounts"`
}

type ProxyPort struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Enabled  bool   `json:"enabled"`
}

type ProxyAccount struct {
	Username string    `json:"username"`
	Password string    `json:"password"`
	Created  time.Time `json:"created"`
	Enabled  bool      `json:"enabled"`
}

type Stats struct {
	TotalConns, ActiveConns, SuccessConns, FailedConns int64
	TimeoutConns         int64
	PoolSize             int64
	StartTime            time.Time
	TotalDuration        int64
	ProcessCPUPercent    int64
	SystemCPUPercent     int64
}

type StatsSnapshot struct {
	Timestamp   string  `json:"timestamp"`
	QPS         float64 `json:"qps"`
	SuccessRate float64 `json:"success_rate"`
	ProcessCPU  float64 `json:"process_cpu"`
	SystemCPU   float64 `json:"system_cpu"`
	ActiveConns int64   `json:"active_conns"`
}

type ConnLog struct {
	Time     string `json:"time"`
	ClientIP string `json:"client_ip"`
	Target   string `json:"target"`
	IPv6     string `json:"ipv6"`
	Status   string `json:"status"`
	Duration string `json:"duration"`
}

type ActiveConn struct {
	ID        string    `json:"id"`
	ClientIP  string    `json:"client_ip"`
	Target    string    `json:"target"`
	IPv6      string    `json:"ipv6"`
	StartTime time.Time `json:"-"`
	Duration  string    `json:"duration"`
}

func readUserChoice(maxChoice int) int {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("选择 (1-%d): ", maxChoice)
		text, _ := reader.ReadString('\n')
		choice, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil || choice < 1 || choice > maxChoice {
			continue
		}
		return choice
	}
}

func readUserInt(prompt string, defaultValue int) int {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s (默认 %d): ", prompt, defaultValue)
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			return defaultValue
		}
		val, err := strconv.Atoi(text)
		if err != nil || val < 0 {
			continue
		}
		return val
	}
}

func readUserString(prompt string, defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s (默认 %s): ", prompt, defaultValue)
	text, _ := reader.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultValue
	}
	return text
}

func readUserPassword(prompt string, defaultValue string) string {
	fmt.Printf("%s (默认 %s): ", prompt, defaultValue)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			return defaultValue
		}
		return text
	}
	text := string(bytePassword)
	if text == "" {
		return defaultValue
	}
	return text
}

func selectInterface() (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var validLinks []netlink.Link
	for _, link := range links {
		if link.Attrs().Flags&net.FlagUp != 0 && link.Attrs().Flags&net.FlagLoopback == 0 {
			validLinks = append(validLinks, link)
		}
	}
	if len(validLinks) == 0 {
		return nil, errors.New("无可用网卡")
	}
	log.Println("可用网卡:")
	for i, link := range validLinks {
		log.Printf("  %d: %s", i+1, link.Attrs().Name)
	}
	choice := readUserChoice(len(validLinks))
	return validLinks[choice-1], nil
}

func selectIPv6Prefix(iface netlink.Link) (string, error) {
	addrs, err := netlink.AddrList(iface, netlink.FAMILY_V6)
	if err != nil {
		return "", err
	}
	var prefixes []string
	for _, addr := range addrs {
		ipStr := addr.IP.String()
		if !strings.HasPrefix(ipStr, "fe80") && strings.Contains(ipStr, ":") {
			prefixes = append(prefixes, addr.IPNet.String())
		}
	}
	if len(prefixes) == 0 {
		return "", errors.New("无IPv6地址")
	}
	if len(prefixes) == 1 {
		return prefixes[0], nil
	}
	log.Println("可用IPv6前缀:")
	for i, prefix := range prefixes {
		log.Printf("  %d: %s", i+1, prefix)
	}
	choice := readUserChoice(len(prefixes))
	return prefixes[choice-1], nil
}

func initConfig() error {
	log.Println("\n=== 配置初始化 ===")
	
	log.Println("\n--- 端口 ---")
	config.Port = readUserString("SOCKS5 端口", "1080")
	config.WebPort = readUserString("Web 端口", "8080")
	
	log.Println("\n--- 认证 ---")
	config.Username = readUserString("代理用户名", "proxy")
	config.Password = readUserPassword("代理密码", "proxy123")
	config.WebUsername = readUserString("Web用户名", "admin")
	config.WebPassword = readUserPassword("Web密码", "admin123")

	log.Println("\n--- 网络 ---")
	selectedIface, err := selectInterface()
	if err != nil {
		return err
	}
	config.Interface = selectedIface.Attrs().Name

	selectedPrefix, err := selectIPv6Prefix(selectedIface)
	if err != nil {
		return err
	}
	config.IPv6Prefix = selectedPrefix

	log.Println("\n--- IP 池 ---")
	config.InitialPool = readUserInt("初始池", 10000)
	config.TargetPool = readUserInt("目标池", 100000)
	if config.TargetPool < config.InitialPool {
		config.TargetPool = config.InitialPool
	}
	
	log.Println("\n--- 自动轮换 ---")
	autoRotate := readUserString("启用? (y/n)", "n")
	config.AutoRotate = strings.ToLower(autoRotate) == "y"
	if config.AutoRotate {
		config.AutoRotateHours = readUserInt("间隔(小时)", 6)
	}
	
	log.Println("\n--- 自清理 ---")
	autoClean := readUserString("启用失败IPv6自动清理? (y/n)", "y")
	config.AutoClean = strings.ToLower(autoClean) == "y"
	
	// 初始化默认端口和账户
	config.ProxyPorts = []ProxyPort{
		{Port: config.Port, Protocol: "SOCKS5", Enabled: true},
	}
	config.ProxyAccounts = []ProxyAccount{
		{Username: config.Username, Password: config.Password, Created: time.Now(), Enabled: true},
	}
	
	return nil
}

func saveConfigToFile() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFilePath, data, 0644)
}

func loadConfigFromFile() error {
	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	
	// 同步到全局变量
	proxyPortsLock.Lock()
	proxyPorts = config.ProxyPorts
	proxyPortsLock.Unlock()
	
	accountsLock.Lock()
	proxyAccounts = config.ProxyAccounts
	accountsLock.Unlock()
	
	return nil
}

func generateRandomIP() net.IP {
	rngLock.Lock()
	defer rngLock.Unlock()
	
	ip := make(net.IP, len(prefixIP))
	copy(ip, prefixIP)
	
	for i := 8; i < 16; i++ {
		ip[i] = byte(rng.Intn(256))
	}
	
	if ip[15] == 0 {
		ip[15] = 1
	}
	
	return ip
}

func addIPv6(ip net.IP) error {
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		},
	}
	return netlink.AddrAdd(iface, addr)
}

func delIPv6(ip net.IP) error {
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		},
	}
	return netlink.AddrDel(iface, addr)
}

func buildInitialPool(ctx context.Context) {
	targetSize := config.InitialPool
	log.Printf("构建IP池 (目标: %d)...", targetSize)
	
	for i := 0; i < targetSize; i++ {
		select {
		case <-ctx.Done():
			return
		default:
			ip := generateRandomIP()
			if addIPv6(ip) == nil {
				poolLock.Lock()
				ipv6Pool = append(ipv6Pool, ip)
				ipv6PoolIndex[ip.String()] = len(ipv6Pool) - 1
				poolLock.Unlock()
				atomic.AddInt64(&stats.PoolSize, 1)
			}
			
			if (i+1)%1000 == 0 {
				log.Printf("  %d/%d", i+1, targetSize)
			}
		}
	}
	
	log.Printf("✅ IP池就绪: %d个", atomic.LoadInt64(&stats.PoolSize))
	atomic.StoreInt32(&backgroundRunning, 1)
}

func addConnLog(clientIP, target, ipv6, status string, duration time.Duration) {
	log := &ConnLog{
		Time:     time.Now().Format("15:04:05"),
		ClientIP: clientIP,
		Target:   target,
		IPv6:     ipv6,
		Status:   status,
		Duration: fmt.Sprintf("%.0fms", duration.Seconds()*1000),
	}
	
	connLogsLock.Lock()
	connLogs = append(connLogs, log)
	if len(connLogs) > maxLogs {
		connLogs = connLogs[len(connLogs)-maxLogs:]
	}
	connLogsLock.Unlock()
	
	if strings.Contains(status, "❌") || strings.Contains(status, "⏱️") {
		failLogsLock.Lock()
		failLogs = append(failLogs, log)
		if len(failLogs) > maxLogs {
			failLogs = failLogs[len(failLogs)-maxLogs:]
		}
		failLogsLock.Unlock()
	}
}

func autoRotateRoutine(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&autoRotateEnabled) == 1 {
				nextRotateTimeLock.RLock()
				shouldRotate := time.Now().After(nextRotateTime)
				nextRotateTimeLock.RUnlock()
				
				if shouldRotate {
					log.Println("[自动轮换] 开始轮换IP池...")
					rotateIPPool(ctx)
					
					interval := atomic.LoadInt64(&autoRotateInterval)
					nextRotateTimeLock.Lock()
					nextRotateTime = time.Now().Add(time.Duration(interval) * time.Hour)
					nextRotateTimeLock.Unlock()
				}
			}
		}
	}
}

func rotateIPPool(ctx context.Context) {
	poolLock.Lock()
	oldPool := ipv6Pool
	ipv6Pool = []net.IP{}
	ipv6PoolIndex = make(map[string]int)
	poolLock.Unlock()
	
	atomic.StoreInt64(&stats.PoolSize, 0)
	
	for _, ip := range oldPool {
		delIPv6(ip)
	}
	
	targetSize := config.TargetPool
	for i := 0; i < targetSize; i++ {
		select {
		case <-ctx.Done():
			return
		default:
			ip := generateRandomIP()
			if addIPv6(ip) == nil {
				poolLock.Lock()
				ipv6Pool = append(ipv6Pool, ip)
				ipv6PoolIndex[ip.String()] = len(ipv6Pool) - 1
				poolLock.Unlock()
				atomic.AddInt64(&stats.PoolSize, 1)
			}
		}
	}
	
	log.Printf("[轮换完成] 新池大小: %d", atomic.LoadInt64(&stats.PoolSize))
}

func backgroundAddTask(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&backgroundRunning) == 0 {
				continue
			}
			
			currentSize := int(atomic.LoadInt64(&stats.PoolSize))
			if currentSize >= config.TargetPool {
				atomic.StoreInt32(&backgroundRunning, 0)
				continue
			}
			
			for i := 0; i < 50 && currentSize < config.TargetPool; i++ {
				ip := generateRandomIP()
				if addIPv6(ip) == nil {
					poolLock.Lock()
					ipv6Pool = append(ipv6Pool, ip)
					ipv6PoolIndex[ip.String()] = len(ipv6Pool) - 1
					poolLock.Unlock()
					atomic.AddInt64(&stats.PoolSize, 1)
					atomic.AddInt64(&backgroundAdded, 1)
					currentSize++
				}
			}
		}
	}
}

func discardWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	batch := make([]net.IP, 0, 1000)
	
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-discardQueue:
			batch = append(batch, ip)
			if len(batch) >= 100 {
				processBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				processBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func processBatch(ips []net.IP) {
	if len(ips) == 0 {
		return
	}
	
	for _, ip := range ips {
		delIPv6(ip)
	}
	
	poolLock.Lock()
	for _, ip := range ips {
		ipString := ip.String()
		if index, ok := ipv6PoolIndex[ipString]; ok {
			lastIP := ipv6Pool[len(ipv6Pool)-1]
			ipv6Pool[index] = lastIP
			ipv6PoolIndex[lastIP.String()] = index
			ipv6Pool = ipv6Pool[:len(ipv6Pool)-1]
			delete(ipv6PoolIndex, ipString)
		}
	}
	poolLock.Unlock()
	
	newSize := atomic.AddInt64(&stats.PoolSize, -int64(len(ips)))
	if int(newSize) < config.TargetPool {
		atomic.StoreInt32(&backgroundRunning, 1)
	}
}

func getRandomIP() net.IP {
	poolLock.RLock()
	if len(ipv6Pool) == 0 {
		poolLock.RUnlock()
		return nil
	}
	rngLock.Lock()
	index := rng.Intn(len(ipv6Pool))
	rngLock.Unlock()
	ip := ipv6Pool[index]
	poolLock.RUnlock()
	return ip
}

func checkAuth(user, pass string) bool {
	accountsLock.RLock()
	defer accountsLock.RUnlock()
	
	for _, acc := range proxyAccounts {
		if acc.Enabled && acc.Username == user && acc.Password == pass {
			return true
		}
	}
	return false
}

func transfer(dst net.Conn, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	deadline := time.Now().Add(120 * time.Second)
	src.SetReadDeadline(deadline)
	dst.SetWriteDeadline(deadline)
	buf := make([]byte, 64*1024)
	io.CopyBuffer(dst, src, buf)
}

func handleSOCKS5(conn net.Conn) {
	defer conn.Close()
	defer atomic.AddInt64(&stats.ActiveConns, -1)
	buf := make([]byte, 512)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return
	}
	conn.Write([]byte{5, 2})
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	ulen := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:ulen]); err != nil {
		return
	}
	username := string(buf[:ulen])
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return
	}
	plen := int(buf[0])
	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return
	}
	password := string(buf[:plen])
	if !checkAuth(username, password) {
		conn.Write([]byte{1, 1})
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	conn.Write([]byte{1, 0})
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	var host string
	var port uint16
	atyp := buf[3]
	switch atyp {
	case 1:
		if _, err := io.ReadFull(conn, buf[:6]); err != nil {
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		port = binary.BigEndian.Uint16(buf[4:6])
	case 3:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		dlen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dlen+2]); err != nil {
			return
		}
		host = string(buf[:dlen])
		port = binary.BigEndian.Uint16(buf[dlen : dlen+2])
	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	connectAndProxy(conn, host, port, true)
}

func handleHTTP(conn net.Conn, firstByte byte) {
	defer conn.Close()
	defer atomic.AddInt64(&stats.ActiveConns, -1)
	buf := make([]byte, 4096)
	buf[0] = firstByte
	n, err := conn.Read(buf[1:])
	if err != nil {
		return
	}
	request := string(buf[:n+1])
	lines := strings.Split(request, "\r\n")
	if len(lines) < 1 {
		return
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 3 {
		return
	}
	method := parts[0]
	target := parts[1]
	authorized := false
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "proxy-authorization: basic ") {
			encoded := strings.TrimSpace(line[27:])
			if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
				credentials := strings.SplitN(string(decoded), ":", 2)
				if len(credentials) == 2 && checkAuth(credentials[0], credentials[1]) {
					authorized = true
					break
				}
			}
		}
	}
	if !authorized {
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	if method != "CONNECT" {
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	hostPort := strings.Split(target, ":")
	if len(hostPort) != 2 {
		return
	}
	host := hostPort[0]
	var port uint16
	fmt.Sscanf(hostPort[1], "%d", &port)
	connectAndProxy(conn, host, port, false)
}

func connectAndProxy(clientConn net.Conn, host string, port uint16, isSocks bool) {
	startTime := time.Now()
	clientIP := clientConn.RemoteAddr().String()
	target := fmt.Sprintf("%s:%d", host, port)

	ip := getRandomIP()
	if ip == nil {
		addConnLog(clientIP, target, "N/A", "❌ 无IP", time.Since(startTime))
		if isSocks {
			clientConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			clientConn.Write([]byte("HTTP/1.1 503 Unavailable\r\n\r\n"))
		}
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}

	ipv6String := ip.String()
	
	connID := fmt.Sprintf("%s-%d", clientIP, time.Now().UnixNano())
	activeConn := &ActiveConn{
		ID:        connID,
		ClientIP:  clientIP,
		Target:    target,
		IPv6:      ipv6String,
		StartTime: startTime,
	}
	activeConnectionsLock.Lock()
	activeConnections[connID] = activeConn
	activeConnectionsLock.Unlock()
	
	defer func() {
		activeConnectionsLock.Lock()
		delete(activeConnections, connID)
		activeConnectionsLock.Unlock()
	}()
	
	localAddr := &net.TCPAddr{IP: ip}
	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   15 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	remoteConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		var status string
		shouldDiscard := false
		
		if errors.Is(err, context.DeadlineExceeded) {
			status = "⏱️ 总超时"
			atomic.AddInt64(&stats.TimeoutConns, 1)
			shouldDiscard = true
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			status = "⏱️ 连接超时"
			atomic.AddInt64(&stats.TimeoutConns, 1)
		} else {
			errMsg := err.Error()
			if len(errMsg) > 30 {
				errMsg = errMsg[:30]
			}
			status = fmt.Sprintf("❌ %s", errMsg)
			shouldDiscard = strings.Contains(err.Error(), "refused") ||
				strings.Contains(err.Error(), "unreachable")
		}
		
		addConnLog(clientIP, target, ipv6String, status, time.Since(startTime))
		if isSocks {
			clientConn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		atomic.AddInt64(&stats.FailedConns, 1)
		
		if config.AutoClean && shouldDiscard {
			select {
			case discardQueue <- ip:
			default:
			}
		}
		return
	}
	defer remoteConn.Close()

	atomic.AddInt64(&stats.SuccessConns, 1)
	duration := time.Since(startTime)
	atomic.AddInt64(&stats.TotalDuration, duration.Nanoseconds())
	addConnLog(clientIP, target, ipv6String, "✅ 成功", duration)

	if isSocks {
		clientConn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	} else {
		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(remoteConn, clientConn, &wg)
	go transfer(clientConn, remoteConn, &wg)
	wg.Wait()
}

func handleConnection(conn net.Conn) {
	atomic.AddInt64(&stats.ActiveConns, 1)
	atomic.AddInt64(&stats.TotalConns, 1)
	firstByte := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(firstByte)
	if err != nil {
		conn.Close()
		atomic.AddInt64(&stats.ActiveConns, -1)
		return
	}
	conn.SetReadDeadline(time.Time{})

	if n == 1 && firstByte[0] == 0x05 {
		handleSOCKS5(conn)
	} else if n == 1 {
		handleHTTP(conn, firstByte[0])
	} else {
		conn.Close()
		atomic.AddInt64(&stats.ActiveConns, -1)
	}
}

func statsCPURoutine(ctx context.Context) {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return
	}
	
	p.CPUPercent()
	time.Sleep(10 * time.Second)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			processCPU, err := p.CPUPercent()
			if err == nil {
				atomic.StoreInt64(&stats.ProcessCPUPercent, int64(processCPU*100))
			}
			
			systemCPU, err := cpu.Percent(0, false)
			if err == nil && len(systemCPU) > 0 {
				atomic.StoreInt64(&stats.SystemCPUPercent, int64(systemCPU[0]*100))
			}
		}
	}
}

func statsHistoryRoutine(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			uptime := time.Since(stats.StartTime)
			total := atomic.LoadInt64(&stats.TotalConns)
			qps := 0.0
			if uptime.Seconds() > 0 {
				qps = float64(total) / uptime.Seconds()
			}
			
			success := atomic.LoadInt64(&stats.SuccessConns)
			failed := atomic.LoadInt64(&stats.FailedConns)
			successRate := 0.0
			if total > 0 {
				successRate = float64(success) * 100 / float64(success+failed)
			}
			
			snapshot := &StatsSnapshot{
				Timestamp:   time.Now().Format("15:04:05"),
				QPS:         qps,
				SuccessRate: successRate,
				ProcessCPU:  float64(atomic.LoadInt64(&stats.ProcessCPUPercent)) / 100.0,
				SystemCPU:   float64(atomic.LoadInt64(&stats.SystemCPUPercent)) / 100.0,
				ActiveConns: atomic.LoadInt64(&stats.ActiveConns),
			}
			
			statsHistoryLock.Lock()
			statsHistory = append(statsHistory, snapshot)
			if len(statsHistory) > maxHistory {
				statsHistory = statsHistory[len(statsHistory)-maxHistory:]
			}
			statsHistoryLock.Unlock()
		}
	}
}

func basicAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="管理面板"`)
			http.Error(w, "需要认证", http.StatusUnauthorized)
			return
		}
		
		const prefix = "Basic "
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "无效认证", http.StatusUnauthorized)
			return
		}
		
		decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
		if err != nil {
			http.Error(w, "无效认证", http.StatusUnauthorized)
			return
		}
		
		creds := strings.SplitN(string(decoded), ":", 2)
		if len(creds) != 2 {
			http.Error(w, "无效认证", http.StatusUnauthorized)
			return
		}
		
		usernameMatch := subtle.ConstantTimeCompare([]byte(creds[0]), []byte(config.WebUsername)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(creds[1]), []byte(config.WebPassword)) == 1
		
		if !usernameMatch || !passwordMatch {
			http.Error(w, "认证失败", http.StatusUnauthorized)
			return
		}
		
		handler(w, r)
	}
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(stats.StartTime)
	total := atomic.LoadInt64(&stats.TotalConns)
	qps := 0.0
	if uptime.Seconds() > 0 {
		qps = float64(total) / uptime.Seconds()
	}
	currentPool := atomic.LoadInt64(&stats.PoolSize)
	targetPool := int64(config.TargetPool)
	progress := 0.0
	if targetPool > 0 {
		progress = float64(currentPool) * 100 / float64(targetPool)
		if progress > 100 {
			progress = 100
		}
	}

	var avgDurationMs float64
	successConns := atomic.LoadInt64(&stats.SuccessConns)
	if successConns > 0 {
		avgDurationMs = float64(atomic.LoadInt64(&stats.TotalDuration)) / float64(successConns) / float64(time.Millisecond)
	}

	processCPU := float64(atomic.LoadInt64(&stats.ProcessCPUPercent)) / 100.0
	systemCPU := float64(atomic.LoadInt64(&stats.SystemCPUPercent)) / 100.0

	nextRotateTimeLock.RLock()
	nextRotate := nextRotateTime.Format("2006-01-02 15:04:05")
	nextRotateTimeLock.RUnlock()
	
	proxyPortsLock.RLock()
	portCount := len(proxyPorts)
	activePortCount := 0
	for _, p := range proxyPorts {
		if p.Enabled {
			activePortCount++
		}
	}
	proxyPortsLock.RUnlock()
	
	accountsLock.RLock()
	accountCount := len(proxyAccounts)
	activeAccountCount := 0
	for _, a := range proxyAccounts {
		if a.Enabled {
			activeAccountCount++
		}
	}
	accountsLock.RUnlock()

	data := map[string]interface{}{
		"active":          atomic.LoadInt64(&stats.ActiveConns),
		"total":           total,
		"success":         successConns,
		"failed":          atomic.LoadInt64(&stats.FailedConns),
		"timeout":         atomic.LoadInt64(&stats.TimeoutConns),
		"pool":            currentPool,
		"target":          targetPool,
		"progress":        progress,
		"bg_running":      atomic.LoadInt32(&backgroundRunning) == 1,
		"bg_added":        atomic.LoadInt64(&backgroundAdded),
		"qps":             qps,
		"uptime":          fmt.Sprintf("%dd %dh %dm", int(uptime.Hours())/24, int(uptime.Hours())%24, int(uptime.Minutes())%60),
		"avg_duration":    avgDurationMs,
		"process_cpu":     processCPU,
		"system_cpu":      systemCPU,
		"auto_rotate":     atomic.LoadInt32(&autoRotateEnabled) == 1,
		"rotate_interval": atomic.LoadInt64(&autoRotateInterval),
		"next_rotate":     nextRotate,
		"auto_clean":      config.AutoClean,
		"port_count":      portCount,
		"active_ports":    activePortCount,
		"account_count":   accountCount,
		"active_accounts": activeAccountCount,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func handleAPILogs(w http.ResponseWriter, r *http.Request) {
	connLogsLock.RLock()
	logs := make([]*ConnLog, len(connLogs))
	copy(logs, connLogs)
	connLogsLock.RUnlock()

	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func handleAPIFailLogs(w http.ResponseWriter, r *http.Request) {
	failLogsLock.RLock()
	logs := make([]*ConnLog, len(failLogs))
	copy(logs, failLogs)
	failLogsLock.RUnlock()

	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func handleAPISearchLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]*ConnLog{})
		return
	}

	connLogsLock.RLock()
	var results []*ConnLog
	for _, log := range connLogs {
		if strings.Contains(log.ClientIP, query) ||
		   strings.Contains(log.Target, query) ||
		   strings.Contains(log.IPv6, query) {
			results = append(results, log)
		}
	}
	connLogsLock.RUnlock()

	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleAPIActiveConns(w http.ResponseWriter, r *http.Request) {
	activeConnectionsLock.RLock()
	conns := make([]*ActiveConn, 0, len(activeConnections))
	for _, conn := range activeConnections {
		connCopy := *conn
		connCopy.Duration = fmt.Sprintf("%.0fs", time.Since(conn.StartTime).Seconds())
		conns = append(conns, &connCopy)
	}
	activeConnectionsLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conns)
}

func handleAPIHistory(w http.ResponseWriter, r *http.Request) {
	statsHistoryLock.RLock()
	history := make([]*StatsSnapshot, len(statsHistory))
	copy(history, statsHistory)
	statsHistoryLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func handleAPIPoolResize(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"仅支持POST"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Target int `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"无效请求"}`, http.StatusBadRequest)
		return
	}

	if req.Target < 100 {
		http.Error(w, `{"error":"目标必须 >= 100"}`, http.StatusBadRequest)
		return
	}

	config.TargetPool = req.Target
	saveConfigToFile()
	atomic.StoreInt32(&backgroundRunning, 1)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("目标已设为 %d", req.Target)})
}

func handleAPIRotate(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, `{"error":"仅支持POST"}`, http.StatusMethodNotAllowed)
			return
		}
		
		go rotateIPPool(ctx)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "轮换已启动"})
	}
}

func handleAPIUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"仅支持POST"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Port     string `json:"port"`
		WebPort  string `json:"web_port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"无效请求"}`, http.StatusBadRequest)
		return
	}

	if req.Port != "" {
		config.Port = req.Port
	}
	if req.WebPort != "" {
		config.WebPort = req.WebPort
	}
	if req.Username != "" {
		config.Username = req.Username
	}
	if req.Password != "" {
		config.Password = req.Password
	}

	saveConfigToFile()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "配置已保存，需重启服务"})
}

func handleAPIAutoRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"仅支持POST"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled  bool `json:"enabled"`
		Interval int  `json:"interval"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"无效请求"}`, http.StatusBadRequest)
		return
	}

	if req.Interval < 1 {
		req.Interval = 6
	}

	config.AutoRotate = req.Enabled
	config.AutoRotateHours = req.Interval
	saveConfigToFile()

	if req.Enabled {
		atomic.StoreInt32(&autoRotateEnabled, 1)
		atomic.StoreInt64(&autoRotateInterval, int64(req.Interval))
		nextRotateTimeLock.Lock()
		nextRotateTime = time.Now().Add(time.Duration(req.Interval) * time.Hour)
		nextRotateTimeLock.Unlock()
	} else {
		atomic.StoreInt32(&autoRotateEnabled, 0)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "设置已更新"})
}

func handleAPIAutoClean(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"仅支持POST"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"无效请求"}`, http.StatusBadRequest)
		return
	}

	config.AutoClean = req.Enabled
	saveConfigToFile()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "自清理设置已更新"})
}

func handleAPIPorts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		proxyPortsLock.RLock()
		ports := make([]ProxyPort, len(proxyPorts))
		copy(ports, proxyPorts)
		proxyPortsLock.RUnlock()
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ports)
		
	case "POST":
		var port ProxyPort
		if err := json.NewDecoder(r.Body).Decode(&port); err != nil {
			http.Error(w, `{"error":"无效请求"}`, http.StatusBadRequest)
			return
		}
		
		proxyPortsLock.Lock()
		proxyPorts = append(proxyPorts, port)
		config.ProxyPorts = proxyPorts
		proxyPortsLock.Unlock()
		
		saveConfigToFile()
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "端口已添加，需重启服务"})
		
	case "DELETE":
		var req struct {
			Port string `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"无效请求"}`, http.StatusBadRequest)
			return
		}
		
		proxyPortsLock.Lock()
		newPorts := []ProxyPort{}
		for _, p := range proxyPorts {
			if p.Port != req.Port {
				newPorts = append(newPorts, p)
			}
		}
		proxyPorts = newPorts
		config.ProxyPorts = proxyPorts
		proxyPortsLock.Unlock()
		
		saveConfigToFile()
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "端口已删除"})
		
	default:
		http.Error(w, `{"error":"不支持的方法"}`, http.StatusMethodNotAllowed)
	}
}

func handleAPIAccounts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		accountsLock.RLock()
		accounts := make([]ProxyAccount, len(proxyAccounts))
		copy(accounts, proxyAccounts)
		accountsLock.RUnlock()
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(accounts)
		
	case "POST":
		var account ProxyAccount
		if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
			http.Error(w, `{"error":"无效请求"}`, http.StatusBadRequest)
			return
		}
		
		account.Created = time.Now()
		account.Enabled = true
		
		accountsLock.Lock()
		proxyAccounts = append(proxyAccounts, account)
		config.ProxyAccounts = proxyAccounts
		accountsLock.Unlock()
		
		saveConfigToFile()
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "账户已添加"})
		
	case "DELETE":
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"无效请求"}`, http.StatusBadRequest)
			return
		}
		
		accountsLock.Lock()
		newAccounts := []ProxyAccount{}
		for _, a := range proxyAccounts {
			if a.Username != req.Username {
				newAccounts = append(newAccounts, a)
			}
		}
		proxyAccounts = newAccounts
		config.ProxyAccounts = proxyAccounts
		accountsLock.Unlock()
		
		saveConfigToFile()
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "账户已删除"})
		
	default:
		http.Error(w, `{"error":"不支持的方法"}`, http.StatusMethodNotAllowed)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile(indexHTMLPath)
	if err != nil {
		http.Error(w, "无法加载页面", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(html)
}

func startWebServer(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", basicAuth(handleIndex))
	mux.HandleFunc("/api/stats", basicAuth(handleAPIStats))
	mux.HandleFunc("/api/logs", basicAuth(handleAPILogs))
	mux.HandleFunc("/api/faillogs", basicAuth(handleAPIFailLogs))
	mux.HandleFunc("/api/search", basicAuth(handleAPISearchLogs))
	mux.HandleFunc("/api/active", basicAuth(handleAPIActiveConns))
	mux.HandleFunc("/api/history", basicAuth(handleAPIHistory))
	mux.HandleFunc("/api/pool/resize", basicAuth(handleAPIPoolResize))
	mux.HandleFunc("/api/rotate", basicAuth(handleAPIRotate(ctx)))
	mux.HandleFunc("/api/config", basicAuth(handleAPIUpdateConfig))
	mux.HandleFunc("/api/autorotate", basicAuth(handleAPIAutoRotate))
	mux.HandleFunc("/api/autoclean", basicAuth(handleAPIAutoClean))
	mux.HandleFunc("/api/ports", basicAuth(handleAPIPorts))
	mux.HandleFunc("/api/accounts", basicAuth(handleAPIAccounts))

	srv := &http.Server{
		Addr:    ":" + config.WebPort,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()

	log.Printf("Web面板: http://0.0.0.0:%s (用户: %s)", config.WebPort, config.WebUsername)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Web服务错误: %v", err)
	}
}

func startProxyServers(ctx context.Context) {
	proxyPortsLock.RLock()
	ports := make([]ProxyPort, len(proxyPorts))
	copy(ports, proxyPorts)
	proxyPortsLock.RUnlock()
	
	for _, port := range ports {
		if !port.Enabled {
			continue
		}
		
		go func(p ProxyPort) {
			listener, err := net.Listen("tcp", ":"+p.Port)
			if err != nil {
				log.Printf("端口 %s 启动失败: %v", p.Port, err)
				return
			}
			defer listener.Close()
			
			log.Printf("%s 代理服务: 0.0.0.0:%s", p.Protocol, p.Port)
			
			go func() {
				<-ctx.Done()
				listener.Close()
			}()
			
			for {
				conn, err := listener.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				go handleConnection(conn)
			}
		}(port)
	}
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime)
	
	configFilePath = filepath.Join(os.Getenv("PWD"), "config.json")
	indexHTMLPath = filepath.Join(os.Getenv("PWD"), "index.html")
	
	if err := loadConfigFromFile(); err != nil {
		if err := initConfig(); err != nil {
			log.Fatalf("配置初始化失败: %v", err)
		}
		saveConfigToFile()
	}
	
	var err error
	iface, err = netlink.LinkByName(config.Interface)
	if err != nil {
		log.Fatalf("获取网卡失败: %v", err)
	}
	
	prefixIP, prefixNet, err = net.ParseCIDR(config.IPv6Prefix)
	if err != nil {
		log.Fatalf("解析IPv6前缀失败: %v", err)
	}
	
	if config.AutoRotate {
		atomic.StoreInt32(&autoRotateEnabled, 1)
		atomic.StoreInt64(&autoRotateInterval, int64(config.AutoRotateHours))
		nextRotateTimeLock.Lock()
		nextRotateTime = time.Now().Add(time.Duration(config.AutoRotateHours) * time.Hour)
		nextRotateTimeLock.Unlock()
	}
	
	stats.StartTime = time.Now()
	discardQueue = make(chan net.IP, 10000)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	go buildInitialPool(ctx)
	go backgroundAddTask(ctx)
	go discardWorker(ctx)
	go statsCPURoutine(ctx)
	go statsHistoryRoutine(ctx)
	go autoRotateRoutine(ctx)
	go startWebServer(ctx)
	
	time.Sleep(2 * time.Second)
	startProxyServers(ctx)
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	
	log.Println("\n正在关闭...")
	cancel()
	time.Sleep(2 * time.Second)
}
GOEOF

echo "✅ 源码完成"
echo ""

# --- 创建HTML界面 ---
echo "--- 步骤 4: 创建前端界面 ---"
cat << 'HTMLEOF' > index.html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IPv6 代理管理面板 v7.5</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {margin:0;padding:0;box-sizing:border-box}
        
        :root {
            --primary: #8b5cf6;
            --primary-dark: #7c3aed;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #3b82f6;
            --dark: #1e293b;
            --darker: #0f172a;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: rgba(148, 163, 184, 0.1);
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, var(--darker) 0%, #1a1f3a 100%);
            color: var(--text);
            min-height: 100vh;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        
        h1 {
            font-size: 32px;
            font-weight: bold;
            background: linear-gradient(135deg, var(--primary) 0%, var(--info) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .stats-time {
            color: var(--text-muted);
            font-size: 14px;
        }
        
        .cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: var(--dark);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(139, 92, 246, 0.1);
        }
        
        .card-accent {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--info));
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .card-title {
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .card-icon {
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .card-value {
            font-size: 32px;
            font-weight: bold;
            color: var(--text);
            line-height: 1;
            margin-bottom: 8px;
        }
        
        .card-sub {
            font-size: 12px;
            color: var(--text-muted);
        }
        
        .card-action {
            margin-top: 15px;
        }
        
        .btn {
            background: var(--primary);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        
        .btn:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
        }
        
        .btn-success {
            background: var(--success);
        }
        
        .btn-success:hover {
            background: #059669;
        }
        
        .btn-danger {
            background: var(--danger);
        }
        
        .btn-danger:hover {
            background: #dc2626;
        }
        
        .btn-secondary {
            background: rgba(148, 163, 184, 0.2);
        }
        
        .btn-secondary:hover {
            background: rgba(148, 163, 184, 0.3);
        }
        
        .switch {
            position: relative;
            width: 48px;
            height: 24px;
            background: rgba(148, 163, 184, 0.2);
            border-radius: 12px;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .switch input {
            display: none;
        }
        
        .switch-slider {
            position: absolute;
            top: 2px;
            left: 2px;
            width: 20px;
            height: 20px;
            background: white;
            border-radius: 50%;
            transition: transform 0.3s;
        }
        
        .switch input:checked + .switch-slider {
            transform: translateX(24px);
        }
        
        input:checked ~ .switch {
            background: var(--primary);
        }
        
        .input-field {
            background: rgba(51, 65, 85, 0.3);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 14px;
            width: 100%;
            transition: all 0.3s;
        }
        
        .input-field:focus {
            outline: none;
            border-color: var(--primary);
            background: rgba(51, 65, 85, 0.5);
        }
        
        .input-group {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }
        
        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }
        
        .status-active {
            background: rgba(16, 185, 129, 0.2);
            color: var(--success);
        }
        
        .status-inactive {
            background: rgba(148, 163, 184, 0.2);
            color: var(--text-muted);
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(148, 163, 184, 0.1);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--info));
            transition: width 0.5s ease;
            border-radius: 4px;
        }
        
        .section {
            background: var(--dark);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
        }
        
        .section-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.3s;
            color: var(--text-muted);
        }
        
        .tab.active {
            color: var(--primary);
            border-bottom-color: var(--primary);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
        }
        
        th {
            color: var(--text-muted);
            font-weight: 600;
        }
        
        .chart-container {
            height: 250px;
            margin-top: 20px;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: var(--dark);
            border-radius: 12px;
            padding: 24px;
            max-width: 500px;
            width: 90%;
            border: 1px solid var(--border);
        }
        
        .modal-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-label {
            display: block;
            font-size: 14px;
            color: var(--text-muted);
            margin-bottom: 5px;
        }
        
        .success {color: var(--success)}
        .fail {color: var(--danger)}
        .warning {color: var(--warning)}
        
        @media (max-width: 768px) {
            .cards-grid {
                grid-template-columns: 1fr;
            }
            
            .header {
                flex-direction: column;
                gap: 15px;
            }
            
            h1 {
                font-size: 24px;
            }
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🚀 IPv6 代理管理面板</h1>
        <div class="stats-time">
            <span id="current-time"></span> | 运行时间: <span id="uptime">-</span>
        </div>
    </div>
    
    <!-- 数据统计卡片 -->
    <div class="cards-grid">
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">📊</span>
                    活跃连接
                </div>
            </div>
            <div class="card-value" id="active">0</div>
            <div class="card-sub">QPS: <span id="qps">0</span></div>
        </div>
        
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">🔗</span>
                    总连接数
                </div>
            </div>
            <div class="card-value" id="total">0</div>
            <div class="card-sub">成功率: <span id="success-rate">0%</span></div>
        </div>
        
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">✅</span>
                    连接统计
                </div>
            </div>
            <div class="card-value">
                <span class="success" id="success">0</span> / <span class="fail" id="failed">0</span>
            </div>
            <div class="card-sub">超时: <span id="timeout">0</span> | 平均: <span id="avg-duration">0</span>ms</div>
        </div>
        
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">💻</span>
                    系统资源
                </div>
            </div>
            <div class="card-value" style="font-size: 24px;">
                <span id="process-cpu">0</span>% / <span id="system-cpu">0</span>%
            </div>
            <div class="card-sub">进程 CPU / 系统 CPU</div>
        </div>
        
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">🌐</span>
                    IPv6 池
                </div>
                <span class="status-badge" id="pool-status">就绪</span>
            </div>
            <div class="card-value" id="pool-size">0</div>
            <div class="card-sub">目标: <span id="pool-target">0</span></div>
            <div class="progress-bar">
                <div class="progress-fill" id="pool-progress"></div>
            </div>
        </div>
        
        <!-- 配置卡片 -->
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">🔄</span>
                    自动轮换
                </div>
                <label class="switch">
                    <input type="checkbox" id="auto-rotate-enabled" onchange="toggleAutoRotate()">
                    <span class="switch-slider"></span>
                </label>
            </div>
            <div class="card-value" style="font-size: 16px;" id="rotate-status">关闭</div>
            <div class="card-sub" id="next-rotate">-</div>
            <div class="input-group">
                <input type="number" class="input-field" id="rotate-hours" value="6" min="1" max="168" placeholder="小时">
                <button class="btn btn-sm" onclick="saveAutoRotate()">保存</button>
            </div>
        </div>
        
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">🧹</span>
                    自清理
                </div>
                <label class="switch">
                    <input type="checkbox" id="auto-clean-enabled" onchange="toggleAutoClean()">
                    <span class="switch-slider"></span>
                </label>
            </div>
            <div class="card-value" style="font-size: 16px;" id="clean-status">关闭</div>
            <div class="card-sub">失败IPv6自动删除补入</div>
        </div>
        
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">🚪</span>
                    端口管理
                </div>
                <button class="btn btn-sm btn-success" onclick="showAddPortModal()">+ 添加</button>
            </div>
            <div class="card-value" style="font-size: 24px;">
                <span id="active-ports">0</span> / <span id="total-ports">0</span>
            </div>
            <div class="card-sub">活跃端口 / 总端口</div>
            <div class="card-action">
                <button class="btn btn-sm btn-secondary" onclick="showPortsList()">查看列表</button>
            </div>
        </div>
        
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">👤</span>
                    代理账户
                </div>
                <button class="btn btn-sm btn-success" onclick="showAddAccountModal()">+ 添加</button>
            </div>
            <div class="card-value" style="font-size: 24px;">
                <span id="active-accounts">0</span> / <span id="total-accounts">0</span>
            </div>
            <div class="card-sub">活跃账户 / 总账户</div>
            <div class="card-action">
                <button class="btn btn-sm btn-secondary" onclick="showAccountsList()">查看列表</button>
            </div>
        </div>
        
        <div class="card">
            <div class="card-accent"></div>
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">⚡</span>
                    快速操作
                </div>
            </div>
            <div style="display: flex; flex-direction: column; gap: 10px;">
                <button class="btn btn-danger" onclick="rotateNow()">🔄 立即轮换</button>
                <button class="btn btn-secondary" onclick="resizePool()">📏 调整池大小</button>
                <button class="btn btn-secondary" onclick="exportConfig()">💾 导出配置</button>
            </div>
        </div>
    </div>
    
    <!-- 图表区域 -->
    <div class="section">
        <div class="section-title">📊 实时监控</div>
        <div class="chart-container">
            <canvas id="statsChart"></canvas>
        </div>
    </div>
    
    <!-- 日志区域 -->
    <div class="section">
        <div class="section-title">📝 连接日志</div>
        <div class="tabs">
            <div class="tab active" onclick="switchTab(event, 'all-logs')">所有日志</div>
            <div class="tab" onclick="switchTab(event, 'fail-logs')">失败日志</div>
            <div class="tab" onclick="switchTab(event, 'active-conns')">活跃连接</div>
        </div>
        <div id="all-logs" class="tab-content active">
            <table>
                <thead>
                    <tr>
                        <th>时间</th>
                        <th>客户端</th>
                        <th>目标</th>
                        <th>IPv6</th>
                        <th>状态</th>
                        <th>耗时</th>
                    </tr>
                </thead>
                <tbody id="logs-table"></tbody>
            </table>
        </div>
        <div id="fail-logs" class="tab-content">
            <table>
                <thead>
                    <tr>
                        <th>时间</th>
                        <th>客户端</th>
                        <th>目标</th>
                        <th>IPv6</th>
                        <th>状态</th>
                        <th>耗时</th>
                    </tr>
                </thead>
                <tbody id="fail-logs-table"></tbody>
            </table>
        </div>
        <div id="active-conns" class="tab-content">
            <table>
                <thead>
                    <tr>
                        <th>客户端</th>
                        <th>目标</th>
                        <th>IPv6</th>
                        <th>持续时间</th>
                    </tr>
                </thead>
                <tbody id="active-table"></tbody>
            </table>
        </div>
    </div>
</div>

<!-- 添加端口模态框 -->
<div id="port-modal" class="modal">
    <div class="modal-content">
        <div class="modal-title">添加代理端口</div>
        <div class="form-group">
            <label class="form-label">端口号</label>
            <input type="text" class="input-field" id="new-port" placeholder="例如: 1081">
        </div>
        <div class="form-group">
            <label class="form-label">协议类型</label>
            <select class="input-field" id="new-protocol">
                <option value="SOCKS5">SOCKS5</option>
                <option value="HTTP">HTTP</option>
            </select>
        </div>
        <div class="input-group">
            <button class="btn btn-success" onclick="addPort()">添加</button>
            <button class="btn btn-secondary" onclick="closeModal('port-modal')">取消</button>
        </div>
    </div>
</div>

<!-- 添加账户模态框 -->
<div id="account-modal" class="modal">
    <div class="modal-content">
        <div class="modal-title">添加代理账户</div>
        <div class="form-group">
            <label class="form-label">用户名</label>
            <input type="text" class="input-field" id="new-username" placeholder="用户名">
        </div>
        <div class="form-group">
            <label class="form-label">密码</label>
            <input type="password" class="input-field" id="new-password" placeholder="密码">
        </div>
        <div class="input-group">
            <button class="btn btn-success" onclick="addAccount()">添加</button>
            <button class="btn btn-secondary" onclick="closeModal('account-modal')">取消</button>
        </div>
    </div>
</div>

<script>
let statsChart;

function initChart() {
    const ctx = document.getElementById('statsChart').getContext('2d');
    statsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'QPS',
                data: [],
                borderColor: '#8b5cf6',
                tension: 0.3
            }, {
                label: '成功率',
                data: [],
                borderColor: '#10b981',
                tension: 0.3,
                yAxisID: 'y1'
            }, {
                label: 'CPU %',
                data: [],
                borderColor: '#f59e0b',
                tension: 0.3,
                yAxisID: 'y1'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    position: 'left'
                },
                y1: {
                    beginAtZero: true,
                    position: 'right',
                    max: 100,
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    });
}

function updateTime() {
    const now = new Date();
    document.getElementById('current-time').textContent = now.toLocaleString('zh-CN');
}

async function updateStats() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        document.getElementById('active').textContent = data.active;
        document.getElementById('total').textContent = data.total;
        document.getElementById('qps').textContent = data.qps.toFixed(2);
        document.getElementById('success').textContent = data.success;
        document.getElementById('failed').textContent = data.failed;
        document.getElementById('timeout').textContent = data.timeout;
        document.getElementById('process-cpu').textContent = data.process_cpu.toFixed(1);
        document.getElementById('system-cpu').textContent = data.system_cpu.toFixed(1);
        document.getElementById('avg-duration').textContent = data.avg_duration.toFixed(0);
        document.getElementById('pool-size').textContent = data.pool;
        document.getElementById('pool-target').textContent = data.target;
        document.getElementById('pool-progress').style.width = data.progress.toFixed(1) + '%';
        document.getElementById('uptime').textContent = data.uptime;
        
        const successRate = data.total > 0 ? (data.success / (data.success + data.failed) * 100).toFixed(1) : 0;
        document.getElementById('success-rate').textContent = successRate + '%';
        
        document.getElementById('pool-status').textContent = data.bg_running ? '运行中' : '就绪';
        document.getElementById('pool-status').className = data.bg_running ? 'status-badge status-active' : 'status-badge status-inactive';
        
        document.getElementById('auto-rotate-enabled').checked = data.auto_rotate;
        document.getElementById('rotate-status').textContent = data.auto_rotate ? '开启' : '关闭';
        if (data.auto_rotate) {
            document.getElementById('next-rotate').textContent = '下次轮换: ' + data.next_rotate;
        } else {
            document.getElementById('next-rotate').textContent = '未启用自动轮换';
        }
        
        document.getElementById('auto-clean-enabled').checked = data.auto_clean;
        document.getElementById('clean-status').textContent = data.auto_clean ? '开启' : '关闭';
        
        document.getElementById('active-ports').textContent = data.active_ports || 0;
        document.getElementById('total-ports').textContent = data.port_count || 0;
        document.getElementById('active-accounts').textContent = data.active_accounts || 0;
        document.getElementById('total-accounts').textContent = data.account_count || 0;
    } catch (e) {
        console.error('Stats update error:', e);
    }
}

async function updateChart() {
    try {
        const res = await fetch('/api/history');
        const history = await res.json();
        
        if (history.length > 0) {
            statsChart.data.labels = history.map(h => h.timestamp);
            statsChart.data.datasets[0].data = history.map(h => h.qps);
            statsChart.data.datasets[1].data = history.map(h => h.success_rate);
            statsChart.data.datasets[2].data = history.map(h => h.process_cpu);
            statsChart.update('none');
        }
    } catch (e) {
        console.error('Chart update error:', e);
    }
}

async function updateLogs() {
    try {
        const res = await fetch('/api/logs');
        const logs = await res.json();
        
        const tbody = document.getElementById('logs-table');
        tbody.innerHTML = logs.map(log => `
            <tr>
                <td>${log.time}</td>
                <td>${log.client_ip}</td>
                <td>${log.target}</td>
                <td>${log.ipv6}</td>
                <td class="${log.status.includes('✅') ? 'success' : log.status.includes('⏱') ? 'warning' : 'fail'}">${log.status}</td>
                <td>${log.duration}</td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Logs update error:', e);
    }
}

async function updateFailLogs() {
    try {
        const res = await fetch('/api/faillogs');
        const logs = await res.json();
        
        const tbody = document.getElementById('fail-logs-table');
        tbody.innerHTML = logs.map(log => `
            <tr>
                <td>${log.time}</td>
                <td>${log.client_ip}</td>
                <td>${log.target}</td>
                <td>${log.ipv6}</td>
                <td class="fail">${log.status}</td>
                <td>${log.duration}</td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Fail logs update error:', e);
    }
}

async function updateActiveConns() {
    try {
        const res = await fetch('/api/active');
        const conns = await res.json();
        
        const tbody = document.getElementById('active-table');
        tbody.innerHTML = conns.map(conn => `
            <tr>
                <td>${conn.client_ip}</td>
                <td>${conn.target}</td>
                <td>${conn.ipv6}</td>
                <td>${conn.duration}</td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Active conns update error:', e);
    }
}

function switchTab(event, tabName) {
    const tabs = document.querySelectorAll('.tab');
    const contents = document.querySelectorAll('.tab-content');
    
    tabs.forEach(t => t.classList.remove('active'));
    contents.forEach(c => c.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(tabName).classList.add('active');
    
    if (tabName === 'fail-logs') {
        updateFailLogs();
    } else if (tabName === 'active-conns') {
        updateActiveConns();
    }
}

async function toggleAutoRotate() {
    const enabled = document.getElementById('auto-rotate-enabled').checked;
    await saveAutoRotate();
}

async function saveAutoRotate() {
    const enabled = document.getElementById('auto-rotate-enabled').checked;
    const hours = parseInt(document.getElementById('rotate-hours').value) || 6;
    
    try {
        const res = await fetch('/api/autorotate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled, interval: hours})
        });
        const data = await res.json();
        alert(data.message);
        updateStats();
    } catch (e) {
        alert('保存失败');
    }
}

async function toggleAutoClean() {
    const enabled = document.getElementById('auto-clean-enabled').checked;
    
    try {
        const res = await fetch('/api/autoclean', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled})
        });
        const data = await res.json();
        alert(data.message);
        updateStats();
    } catch (e) {
        alert('保存失败');
    }
}

async function rotateNow() {
    if (!confirm('确定要立即轮换所有IP吗？')) return;
    
    try {
        const res = await fetch('/api/rotate', {method: 'POST'});
        const data = await res.json();
        alert(data.message);
        updateStats();
    } catch (e) {
        alert('轮换失败');
    }
}

async function resizePool() {
    const target = prompt('输入目标池大小:', '100000');
    if (!target) return;
    
    const targetNum = parseInt(target);
    if (isNaN(targetNum) || targetNum < 100) {
        alert('无效的目标值');
        return;
    }
    
    try {
        const res = await fetch('/api/pool/resize', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: targetNum})
        });
        const data = await res.json();
        alert(data.message);
        updateStats();
    } catch (e) {
        alert('调整失败');
    }
}

function showAddPortModal() {
    document.getElementById('port-modal').classList.add('active');
}

function showAddAccountModal() {
    document.getElementById('account-modal').classList.add('active');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

async function addPort() {
    const port = document.getElementById('new-port').value;
    const protocol = document.getElementById('new-protocol').value;
    
    if (!port) {
        alert('请输入端口号');
        return;
    }
    
    try {
        const res = await fetch('/api/ports', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({port, protocol, enabled: true})
        });
        const data = await res.json();
        alert(data.message);
        closeModal('port-modal');
        updateStats();
    } catch (e) {
        alert('添加失败');
    }
}

async function addAccount() {
    const username = document.getElementById('new-username').value;
    const password = document.getElementById('new-password').value;
    
    if (!username || !password) {
        alert('请输入用户名和密码');
        return;
    }
    
    try {
        const res = await fetch('/api/accounts', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        const data = await res.json();
        alert(data.message);
        closeModal('account-modal');
        updateStats();
    } catch (e) {
        alert('添加失败');
    }
}

async function showPortsList() {
    try {
        const res = await fetch('/api/ports');
        const ports = await res.json();
        
        let html = '端口列表:\n\n';
        ports.forEach(p => {
            html += `${p.port} - ${p.protocol} - ${p.enabled ? '启用' : '禁用'}\n`;
        });
        alert(html);
    } catch (e) {
        alert('获取失败');
    }
}

async function showAccountsList() {
    try {
        const res = await fetch('/api/accounts');
        const accounts = await res.json();
        
        let html = '账户列表:\n\n';
        accounts.forEach(a => {
            html += `${a.username} - ${a.enabled ? '启用' : '禁用'}\n`;
        });
        alert(html);
    } catch (e) {
        alert('获取失败');
    }
}

function exportConfig() {
    window.location.href = '/api/config';
}

// 初始化
initChart();
updateTime();
updateStats();
updateChart();
updateLogs();

// 定时更新
setInterval(updateTime, 1000);
setInterval(updateStats, 3000);
setInterval(updateChart, 5000);
setInterval(updateLogs, 5000);
</script>
</body>
</html>
HTMLEOF

echo "✅ 前端完成"
echo ""

# --- 编译 ---
echo "--- 步骤 5: 编译 ---"
/usr/local/go/bin/go mod init ipv6-proxy >/dev/null 2>&1
/usr/local/go/bin/go mod tidy >/dev/null
echo "编译中..."
CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags "-s -w" -o ipv6-proxy .
echo "✅ 编译完成"
echo ""

# --- 安装 ---
echo "--- 步骤 6: 安装 ---"
mkdir -p "$INSTALL_DIR"
mv ipv6-proxy "$INSTALL_DIR/"
mv index.html "$INSTALL_DIR/"
cd /
rm -rf "$BUILD_DIR"
echo "✅ 安装完成"
echo ""

# --- 服务 ---
echo "--- 步骤 7: 创建服务 ---"
cat << SERVICEEOF > /etc/systemd/system/ipv6-proxy.service
[Unit]
Description=IPv6 Proxy v7.5 优化版
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/ipv6-proxy
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
echo "✅ 服务创建完成"
echo ""

# --- 配置 ---
echo "============================================="
echo "【首次配置】"
echo "============================================="
echo ""

sudo $INSTALL_DIR/ipv6-proxy || true

echo ""
echo "✅ 配置完成"
echo ""

# --- 防火墙 ---
echo "【配置防火墙】"
if command -v ufw >/dev/null 2>&1; then
    if [ -f "$INSTALL_DIR/config.json" ]; then
        PROXY_PORT=$(grep -oP '"port"\s*:\s*"\K[^"]+' "$INSTALL_DIR/config.json" 2>/dev/null || echo "1080")
        WEB_PORT=$(grep -oP '"web_port"\s*:\s*"\K[^"]+' "$INSTALL_DIR/config.json" 2>/dev/null || echo "8080")
    else
        PROXY_PORT="1080"
        WEB_PORT="8080"
    fi
    
    echo "开放端口..."
    ufw allow ${PROXY_PORT}/tcp comment "IPv6 Proxy" >/dev/null 2>&1
    ufw allow ${WEB_PORT}/tcp comment "IPv6 Web Panel" >/dev/null 2>&1
    
    echo "✅ 防火墙已配置"
    echo "   代理: ${PROXY_PORT}/tcp"
    echo "   Web: ${WEB_PORT}/tcp"
else
    PROXY_PORT="1080"
    WEB_PORT="8080"
    echo "⚠️  未检测到 ufw"
    echo "   手动配置: ufw allow ${PROXY_PORT}/tcp"
    echo "   手动配置: ufw allow ${WEB_PORT}/tcp"
fi
echo ""

# --- 启动 ---
echo "【启动服务】"
systemctl enable ipv6-proxy >/dev/null 2>&1
systemctl start ipv6-proxy

echo ""
echo "================================================"
echo "🎉 v7.5 优化版安装成功！"
echo "================================================"
echo ""
echo "Web 面板: http://$(curl -s ifconfig.me 2>/dev/null || echo '你的IP'):${WEB_PORT}"
echo "  账号: admin"
echo "  密码: admin123"
echo ""
echo "代理地址: $(curl -s ifconfig.me 2>/dev/null || echo '你的IP'):${PROXY_PORT}"
echo "  用户: proxy"
echo "  密码: proxy123"
echo ""
echo "新特性:"
echo "  ✨ 统一卡片式界面"
echo "  ✨ 多端口管理"
echo "  ✨ 多代理账户"
echo "  ✨ 一键操作设计"
echo ""
echo "管理命令:"
echo "  systemctl status ipv6-proxy"
echo "  journalctl -u ipv6-proxy -f"
echo "  systemctl restart ipv6-proxy"
echo ""
echo "🎊 享受 v7.5 优化版！"
echo ""
