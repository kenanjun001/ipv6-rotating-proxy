#!/bin/bash
#
# IPv6 代理 v8.0 Final Plus (终极完整版)
# 
# 新增功能：
# 🔥 自动清理多余进程（超过5个自动杀最旧的）
# 🔥 进程管理面板（点击CPU卡片显示）
# 🔥 手动杀死进程按钮
# 
# 完整功能：
# 🎨 卡片式配置界面
# 🔌 多端口动态管理
# ⚡ 5分钟强制超时
# ✅ 完整泄漏修复
# ✅ 无锁随机优化
# ✅ 批量删除优化
# ✅ NDP 自动清理
#

set -e

INSTALL_DIR="/opt/ipv6-proxy"
BUILD_DIR="/root/ipv6-proxy-build"
GO_VERSION="1.21.5"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=/usr/local/go/bin:$PATH:$GOPATH/bin

if [ "$(id -u)" -ne 0 ]; then
  echo "❌ 需要 root 权限"
  exit 1
fi

echo "============================================="
echo "=== IPv6 代理 v8.0 Final Plus 安装开始 ==="
echo "===     终极完整版 - 进程管理增强      ==="
echo "============================================="

# --- 清理 ---
echo "--- 步骤 1: 清理旧版本 ---"
systemctl stop ipv6-proxy.service 2>/dev/null || true
systemctl disable ipv6-proxy.service 2>/dev/null || true
killall -9 ipv6-proxy 2>/dev/null || true
sleep 2
rm -f /etc/systemd/system/ipv6-proxy.service
rm -rf /opt/ipv6-proxy* /etc/ipv6-proxy /home/ubuntu/geminiip /root/ip "$BUILD_DIR"
systemctl daemon-reload
echo "✅ 清理完成"

# --- 系统优化 ---
echo "--- 步骤 2: 系统优化 ---"
cat > /etc/sysctl.d/99-ipv6-proxy.conf << 'SYSCTLEOF'
# IPv6 代理优化参数 v8.0
net.ipv6.neigh.default.gc_thresh1 = 2048
net.ipv6.neigh.default.gc_thresh2 = 4096
net.ipv6.neigh.default.gc_thresh3 = 8192
net.ipv6.neigh.default.gc_stale_time = 60
net.ipv6.neigh.default.gc_interval = 30
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 8192
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
fs.file-max = 1000000
vm.swappiness = 10
SYSCTLEOF

sysctl -p /etc/sysctl.d/99-ipv6-proxy.conf >/dev/null 2>&1
echo "✅ 系统优化完成"

# --- 安装 Go ---
echo "--- 步骤 3: 安装 Go ---"
apt-get update >/dev/null 2>&1
apt-get install -y wget bc >/dev/null 2>&1

if [ ! -d "/usr/local/go" ] || ! /usr/local/go/bin/go version | grep -q "$GO_VERSION"; then
  echo "正在下载 Go $GO_VERSION..."
  wget -q "$GO_URL" -O "/tmp/$GO_TAR"
  tar -C /usr/local -xzf "/tmp/$GO_TAR"
  rm "/tmp/$GO_TAR"
fi

/usr/local/go/bin/go version
echo "✅ Go 就绪"

# --- 创建源代码 ---
echo "--- 步骤 4: 创建 v8.0 Final Plus 源代码 ---"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cat << 'MAINEOF' > main.go
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
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
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

const (
	maxPoolSize         = 50000
	batchDeleteSize     = 100
	maxConcurrentConns  = 2000
	connectionTimeout   = 5 * time.Minute
	transferTimeout     = 30 * time.Second
	zombieCheckInterval = 2 * time.Minute
	maxProcessCount     = 5  // 最大进程数
	processCheckInterval = 1 * time.Minute  // 进程检查间隔
)

var (
	config            Config
	stats             Stats
	ipv6Pool          []net.IP
	ipv6PoolIndex     map[string]int
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

	discardQueue      chan net.IP
	discardBatch      []net.IP
	discardBatchLock  sync.Mutex
	
	randomCounter     uint64
	connectionSemaphore chan struct{}

	proxyPorts        map[string]*ProxyPort
	proxyPortsLock    sync.RWMutex
	listeners         map[string]net.Listener
	listenersLock     sync.Mutex

	iface     netlink.Link
	prefixIP  net.IP
	prefixNet *net.IPNet

	configFilePath string
	indexHTMLPath  string
)

type ProxyPort struct {
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
}

type Config struct {
	WebPort         string                `json:"web_port"`
	WebUsername     string                `json:"web_username"`
	WebPassword     string                `json:"web_password"`
	IPv6Prefix      string                `json:"ipv6_prefix"`
	Interface       string                `json:"interface"`
	InitialPool     int                   `json:"initial_pool"`
	TargetPool      int                   `json:"target_pool"`
	AutoRotate      bool                  `json:"auto_rotate"`
	AutoRotateHours int                   `json:"auto_rotate_hours"`
	ProxyPorts      map[string]*ProxyPort `json:"proxy_ports"`
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
	Port     string `json:"port"`
}

type ActiveConn struct {
	ID        string    `json:"id"`
	ClientIP  string    `json:"client_ip"`
	Target    string    `json:"target"`
	IPv6      string    `json:"ipv6"`
	Port      string    `json:"port"`
	StartTime time.Time `json:"-"`
	Duration  string    `json:"duration"`
	CancelFunc context.CancelFunc `json:"-"`
}

type ProcessInfo struct {
	PID        int32   `json:"pid"`
	StartTime  int64   `json:"start_time"`
	CPUPercent float64 `json:"cpu_percent"`
	MemoryMB   float64 `json:"memory_mb"`
	UpTime     string  `json:"uptime"`
}

func readUserChoice(maxChoice int) int {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("请输入 (1-%d): ", maxChoice)
		text, _ := reader.ReadString('\n')
		choice, err := strconv.Atoi(strings.TrimSpace(text))
		if err == nil && choice >= 1 && choice <= maxChoice {
			return choice
		}
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
		if val, err := strconv.Atoi(text); err == nil && val >= 0 {
			return val
		}
	}
}

func readUserString(prompt string, defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s (默认 %s): ", prompt, defaultValue)
	text, _ := reader.ReadString('\n')
	if text = strings.TrimSpace(text); text == "" {
		return defaultValue
	}
	return text
}

func readUserPassword(prompt string, defaultValue string) string {
	fmt.Printf("%s (默认 %s): ", prompt, defaultValue)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil || len(bytePassword) == 0 {
		return defaultValue
	}
	return string(bytePassword)
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
	return validLinks[readUserChoice(len(validLinks))-1], nil
}

func selectIPv6Prefix(iface netlink.Link) (string, error) {
	addrs, err := netlink.AddrList(iface, netlink.FAMILY_V6)
	if err != nil {
		return "", err
	}
	prefixMap := make(map[string]bool)
	for _, addr := range addrs {
		if addr.IPNet != nil && addr.IPNet.IP.IsGlobalUnicast() {
			ones, bits := addr.IPNet.Mask.Size()
			if bits == 128 && ones <= 64 {
				ip64 := addr.IPNet.IP.Mask(net.CIDRMask(64, 128))
				prefixStr := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x",
					ip64[0], ip64[1], ip64[2], ip64[3], ip64[4], ip64[5], ip64[6], ip64[7])
				prefixMap[prefixStr] = true
			}
		}
	}
	if len(prefixMap) == 0 {
		log.Println("请输入 IPv6 /64 前缀:")
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		return strings.TrimSpace(text), nil
	}
	var validPrefixes []string
	for prefix := range prefixMap {
		validPrefixes = append(validPrefixes, prefix)
	}
	log.Println("IPv6 前缀:")
	for i, prefix := range validPrefixes {
		log.Printf("  %d: %s", i+1, prefix)
	}
	return validPrefixes[readUserChoice(len(validPrefixes))-1], nil
}

func runInteractiveSetup() error {
	log.Println("--- Web 设置 ---")
	config.WebUsername = readUserString("Web账号", "admin")
	config.WebPassword = readUserPassword("Web密码", "admin123")
	config.WebPort = readUserString("Web端口", "8080")
	
	log.Println("\n--- 代理端口设置 ---")
	port := readUserString("第一个代理端口", "1080")
	username := readUserString("用户名", "proxy")
	password := readUserPassword("密码", "proxy123")
	
	config.ProxyPorts = make(map[string]*ProxyPort)
	config.ProxyPorts[port] = &ProxyPort{
		Port:     port,
		Username: username,
		Password: password,
		Enabled:  true,
	}

	log.Println("\n--- 网络设置 ---")
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

	log.Println("\n--- IP 池设置 ---")
	config.InitialPool = readUserInt("初始池", 10000)
	config.TargetPool = readUserInt("目标池", 30000)
	
	if config.TargetPool > maxPoolSize {
		log.Printf("⚠️ 目标池已调整为 %d", maxPoolSize)
		config.TargetPool = maxPoolSize
	}
	if config.TargetPool < config.InitialPool {
		config.TargetPool = config.InitialPool
	}
	
	log.Println("\n--- 自动轮换 ---")
	autoRotate := readUserString("启用? (y/n)", "n")
	config.AutoRotate = strings.ToLower(autoRotate) == "y"
	if config.AutoRotate {
		config.AutoRotateHours = readUserInt("间隔(小时)", 6)
	}
	
	return nil
}

func saveConfigToFile() error {
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(configFilePath, data, 0644)
}

func loadConfigFromFile() error {
	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &config)
}

func generateRandomIP() net.IP {
	ip := make(net.IP, 16)
	copy(ip, prefixIP)
	if _, err := rand.Read(ip[8:]); err != nil {
		binary.BigEndian.PutUint64(ip[8:], mrand.Uint64())
	}
	return ip
}

func delIPv6(ip net.IP) {
	addr, _ := netlink.ParseAddr(ip.String() + "/128")
	netlink.AddrDel(iface, addr)
}

func addIPv6(ip net.IP) error {
	addr, _ := netlink.ParseAddr(ip.String() + "/128")
	return netlink.AddrAdd(iface, addr)
}

func addConnLog(clientIP, target, ipv6, status, port string, duration time.Duration) {
	connLog := &ConnLog{
		Time:     time.Now().Format("15:04:05"),
		ClientIP: clientIP,
		Target:   target,
		IPv6:     ipv6,
		Status:   status,
		Duration: fmt.Sprintf("%.2fs", duration.Seconds()),
		Port:     port,
	}
	
	connLogsLock.Lock()
	if len(connLogs) >= maxLogs {
		connLogs = connLogs[1:]
	}
	connLogs = append(connLogs, connLog)
	connLogsLock.Unlock()
	
	if !strings.Contains(status, "✅") {
		failLogsLock.Lock()
		if len(failLogs) >= maxLogs {
			failLogs = failLogs[1:]
		}
		failLogs = append(failLogs, connLog)
		failLogsLock.Unlock()
	}
}

func populateIPPool(numToAdd int) ([]net.IP, int) {
	newIPs := make([]net.IP, 0, numToAdd)
	success := 0

	for i := 0; i < numToAdd; i++ {
		ip := generateRandomIP()
		if addIPv6(ip) == nil {
			newIPs = append(newIPs, ip)
			success++
		}
		if term.IsTerminal(int(syscall.Stdin)) && ((i+1)%100 == 0 || (i+1) == numToAdd) {
			fmt.Printf("\r进度: %d/%d ", i+1, numToAdd)
		}
	}
	if term.IsTerminal(int(syscall.Stdin)) && numToAdd > 0 {
		fmt.Println()
	}
	return newIPs, success
}

func initIPv6Pool() error {
	log.Printf("初始化: %d IP", config.InitialPool)
	if config.InitialPool == 0 {
		return nil
	}
	newIPs, success := populateIPPool(config.InitialPool)
	ipv6Pool = newIPs
	ipv6PoolIndex = make(map[string]int, success)
	for i, ip := range newIPs {
		ipv6PoolIndex[ip.String()] = i
	}
	atomic.StoreInt64(&stats.PoolSize, int64(success))
	if success == 0 {
		return fmt.Errorf("初始化失败")
	}
	return nil
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
			if currentSize >= config.TargetPool || currentSize >= maxPoolSize {
				atomic.StoreInt32(&backgroundRunning, 0)
				continue
			}
			for i := 0; i < 50 && currentSize < config.TargetPool && currentSize < maxPoolSize; i++ {
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
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-discardQueue:
			discardBatchLock.Lock()
			discardBatch = append(discardBatch, ip)
			if len(discardBatch) >= batchDeleteSize {
				batch := discardBatch
				discardBatch = make([]net.IP, 0, batchDeleteSize)
				discardBatchLock.Unlock()
				processBatch(batch)
			} else {
				discardBatchLock.Unlock()
			}
		case <-ticker.C:
			discardBatchLock.Lock()
			if len(discardBatch) > 0 {
				batch := discardBatch
				discardBatch = make([]net.IP, 0, batchDeleteSize)
				discardBatchLock.Unlock()
				processBatch(batch)
			} else {
				discardBatchLock.Unlock()
			}
		}
	}
}

func processBatch(ips []net.IP) {
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
	if int(newSize) < config.TargetPool && int(newSize) < maxPoolSize {
		atomic.StoreInt32(&backgroundRunning, 1)
	}
}

func getRandomIP() net.IP {
	poolLock.RLock()
	if len(ipv6Pool) == 0 {
		poolLock.RUnlock()
		return nil
	}
	counter := atomic.AddUint64(&randomCounter, 1)
	nanos := uint64(time.Now().UnixNano())
	index := int((counter ^ nanos) % uint64(len(ipv6Pool)))
	ip := ipv6Pool[index]
	poolLock.RUnlock()
	return ip
}

func checkAuth(user, pass, port string) bool {
	proxyPortsLock.RLock()
	defer proxyPortsLock.RUnlock()
	if p, ok := proxyPorts[port]; ok && p.Enabled {
		return user == p.Username && pass == p.Password
	}
	return false
}

func transfer(dst io.ReadWriteCloser, src io.ReadWriteCloser, wg *sync.WaitGroup, ctx context.Context) {
	defer wg.Done()
	defer dst.Close()
	defer src.Close()
	
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			src.Close()
			dst.Close()
		case <-done:
		}
	}()
	defer close(done)
	
	buf := make([]byte, 32*1024)
	for {
		if err := src.SetReadDeadline(time.Now().Add(transferTimeout)); err != nil {
			break
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if err := dst.SetWriteDeadline(time.Now().Add(transferTimeout)); err != nil {
				break
			}
			if _, ew := dst.Write(buf[0:nr]); ew != nil {
				break
			}
		}
		if er != nil {
			break
		}
	}
}

func handleSOCKS5(conn net.Conn, proxyPort string) {
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
	
	if !checkAuth(username, password, proxyPort) {
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
	
	connectAndProxy(conn, host, port, true, proxyPort)
}

func handleHTTP(conn net.Conn, firstByte byte, proxyPort string) {
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
				if len(credentials) == 2 && checkAuth(credentials[0], credentials[1], proxyPort) {
					authorized = true
					break
				}
			}
		}
	}
	
	if !authorized {
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
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
	var port uint16
	fmt.Sscanf(hostPort[1], "%d", &port)
	
	connectAndProxy(conn, hostPort[0], port, false, proxyPort)
}

func connectAndProxy(clientConn net.Conn, host string, port uint16, isSocks bool, proxyPort string) {
	startTime := time.Now()
	clientIP := clientConn.RemoteAddr().String()
	target := fmt.Sprintf("%s:%d", host, port)

	ip := getRandomIP()
	if ip == nil {
		addConnLog(clientIP, target, "N/A", "❌ 无IP", proxyPort, time.Since(startTime))
		if isSocks {
			clientConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			clientConn.Write([]byte("HTTP/1.1 503\r\n\r\n"))
		}
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}

	ipv6String := ip.String()
	
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()
	
	connID := fmt.Sprintf("%s-%d", clientIP, time.Now().UnixNano())
	activeConn := &ActiveConn{
		ID:         connID,
		ClientIP:   clientIP,
		Target:     target,
		IPv6:       ipv6String,
		Port:       proxyPort,
		StartTime:  startTime,
		CancelFunc: cancel,
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

	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()

	remoteConn, err := dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		var status string
		shouldDiscard := false
		
		if errors.Is(err, context.DeadlineExceeded) {
			status = "⏱️ 超时"
			atomic.AddInt64(&stats.TimeoutConns, 1)
			shouldDiscard = true
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			status = "⏱️ 超时"
			atomic.AddInt64(&stats.TimeoutConns, 1)
		} else {
			errMsg := err.Error()
			if len(errMsg) > 30 {
				errMsg = errMsg[:30]
			}
			status = fmt.Sprintf("❌ %s", errMsg)
			shouldDiscard = strings.Contains(err.Error(), "refused")
		}
		
		addConnLog(clientIP, target, ipv6String, status, proxyPort, time.Since(startTime))
		if isSocks {
			clientConn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			clientConn.Write([]byte("HTTP/1.1 502\r\n\r\n"))
		}
		atomic.AddInt64(&stats.FailedConns, 1)
		
		if shouldDiscard {
			select {
			case discardQueue <- ip:
			default:
			}
		}
		return
	}

	atomic.AddInt64(&stats.SuccessConns, 1)
	duration := time.Since(startTime)
	atomic.AddInt64(&stats.TotalDuration, duration.Nanoseconds())
	addConnLog(clientIP, target, ipv6String, "✅ 成功", proxyPort, duration)

	if isSocks {
		clientConn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	} else {
		clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(remoteConn, clientConn, &wg, ctx)
	go transfer(clientConn, remoteConn, &wg, ctx)
	wg.Wait()
}

func handleConnection(conn net.Conn, proxyPort string) {
	select {
	case connectionSemaphore <- struct{}{}:
		defer func() { <-connectionSemaphore }()
	default:
		conn.Close()
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	
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
		handleSOCKS5(conn, proxyPort)
	} else if n == 1 {
		handleHTTP(conn, firstByte[0], proxyPort)
	} else {
		conn.Close()
		atomic.AddInt64(&stats.ActiveConns, -1)
	}
}

func startProxyListener(ctx context.Context, port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	
	listenersLock.Lock()
	listeners[port] = listener
	listenersLock.Unlock()
	
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	
	go func() {
		log.Printf("✅ 代理端口 %s 已启动", port)
		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					break
				}
				continue
			}
			go handleConnection(conn, port)
		}
		log.Printf("⛔ 代理端口 %s 已停止", port)
	}()
	
	return nil
}

// v8.0 Final Plus 新增：进程管理
func getAllIPv6ProxyProcesses() ([]*ProcessInfo, error) {
	cmd := exec.Command("pgrep", "-f", "ipv6-proxy")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	
	pidStrs := strings.Fields(string(output))
	var processes []*ProcessInfo
	
	for _, pidStr := range pidStrs {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		
		proc, err := process.NewProcess(int32(pid))
		if err != nil {
			continue
		}
		
		createTime, _ := proc.CreateTime()
		cpuPercent, _ := proc.CPUPercent()
		memInfo, _ := proc.MemoryInfo()
		
		uptime := time.Since(time.Unix(createTime/1000, 0))
		memoryMB := 0.0
		if memInfo != nil {
			memoryMB = float64(memInfo.RSS) / 1024 / 1024
		}
		
		processes = append(processes, &ProcessInfo{
			PID:        int32(pid),
			StartTime:  createTime,
			CPUPercent: cpuPercent,
			MemoryMB:   memoryMB,
			UpTime:     fmt.Sprintf("%dd %dh %dm", 
				int(uptime.Hours())/24, 
				int(uptime.Hours())%24, 
				int(uptime.Minutes())%60),
		})
	}
	
	// 按启动时间排序（最早的在前）
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].StartTime < processes[j].StartTime
	})
	
	return processes, nil
}

func processManagerRoutine(ctx context.Context) {
	ticker := time.NewTicker(processCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			processes, err := getAllIPv6ProxyProcesses()
			if err != nil {
				continue
			}
			
			if len(processes) > maxProcessCount {
				// 杀死最早的进程
				toKill := len(processes) - maxProcessCount
				for i := 0; i < toKill; i++ {
					pid := processes[i].PID
					// 不要杀死自己
					if pid != int32(os.Getpid()) {
						proc, err := os.FindProcess(int(pid))
						if err == nil {
							log.Printf("⚠️ 进程数超过 %d，杀死最早的进程 PID=%d", maxProcessCount, pid)
							proc.Kill()
						}
					}
				}
			}
		}
	}
}

func zombieCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(zombieCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			activeConnectionsLock.Lock()
			now := time.Now()
			count := 0
			for id, conn := range activeConnections {
				if now.Sub(conn.StartTime) > connectionTimeout {
					if conn.CancelFunc != nil {
						conn.CancelFunc()
					}
					delete(activeConnections, id)
					count++
				}
			}
			activeConnectionsLock.Unlock()
			if count > 0 {
				log.Printf("清理僵尸连接: %d 个", count)
			}
		}
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
			if processCPU, err := p.CPUPercent(); err == nil {
				atomic.StoreInt64(&stats.ProcessCPUPercent, int64(processCPU*100))
			}
			if systemCPU, err := cpu.Percent(0, false); err == nil && len(systemCPU) > 0 {
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
			successConns := atomic.LoadInt64(&stats.SuccessConns)
			successRate := 0.0
			if total > 0 {
				successRate = float64(successConns) * 100 / float64(total)
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
			if len(statsHistory) >= maxHistory {
				statsHistory = statsHistory[1:]
			}
			statsHistory = append(statsHistory, snapshot)
			statsHistoryLock.Unlock()
		}
	}
}

func statsRoutine(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Printf("📊 活跃:%d 总:%d 成功:%d 失败:%d 池:%d",
				atomic.LoadInt64(&stats.ActiveConns),
				atomic.LoadInt64(&stats.TotalConns),
				atomic.LoadInt64(&stats.SuccessConns),
				atomic.LoadInt64(&stats.FailedConns),
				atomic.LoadInt64(&stats.PoolSize))
		}
	}
}

func logClearRoutine(ctx context.Context) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			connLogsLock.Lock()
			connLogs = []*ConnLog{}
			connLogsLock.Unlock()
			failLogsLock.Lock()
			failLogs = []*ConnLog{}
			failLogsLock.Unlock()
		}
	}
}

func autoRotateRoutine(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&autoRotateEnabled) == 0 {
				continue
			}
			nextRotateTimeLock.RLock()
			shouldRotate := time.Now().After(nextRotateTime)
			nextRotateTimeLock.RUnlock()
			if shouldRotate {
				rotateIPPool(ctx)
				hours := atomic.LoadInt64(&autoRotateInterval)
				nextRotateTimeLock.Lock()
				nextRotateTime = time.Now().Add(time.Duration(hours) * time.Hour)
				nextRotateTimeLock.Unlock()
			}
		}
	}
}

func rotateIPPool(ctx context.Context) {
	atomic.StoreInt32(&backgroundRunning, 0)
	time.Sleep(100 * time.Millisecond)
	newIPs, success := populateIPPool(config.InitialPool)
	if success == 0 {
		if config.TargetPool > int(atomic.LoadInt64(&stats.PoolSize)) {
			atomic.StoreInt32(&backgroundRunning, 1)
		}
		return
	}
	newIPMap := make(map[string]int, success)
	for i, ip := range newIPs {
		newIPMap[ip.String()] = i
	}
	poolLock.Lock()
	oldIPs := ipv6Pool
	ipv6Pool = newIPs
	ipv6PoolIndex = newIPMap
	poolLock.Unlock()
	atomic.StoreInt64(&stats.PoolSize, int64(success))
	log.Printf("✅ 轮换: %d IP", success)
	go cleanupOldIPs(oldIPs)
	if config.TargetPool > success {
		atomic.StoreInt32(&backgroundRunning, 1)
	}
}

func cleanupOldIPs(oldIPs []net.IP) {
	time.Sleep(30 * time.Minute)
	for _, ip := range oldIPs {
		delIPv6(ip)
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
	ports := make([]*ProxyPort, 0, len(proxyPorts))
	for _, p := range proxyPorts {
		ports = append(ports, p)
	}
	proxyPortsLock.RUnlock()
	
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
		"proxy_ports":     ports,
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
	query := strings.ToLower(r.URL.Query().Get("q"))
	if query == "" {
		http.Error(w, `{"error":"缺少q"}`, 400)
		return
	}
	connLogsLock.RLock()
	allLogs := make([]*ConnLog, len(connLogs))
	copy(allLogs, connLogs)
	connLogsLock.RUnlock()
	var results []*ConnLog
	for _, log := range allLogs {
		if strings.Contains(strings.ToLower(log.ClientIP), query) ||
			strings.Contains(strings.ToLower(log.Target), query) ||
			strings.Contains(strings.ToLower(log.IPv6), query) ||
			strings.Contains(strings.ToLower(log.Status), query) ||
			strings.Contains(strings.ToLower(log.Port), query) {
			results = append(results, log)
		}
	}
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
		connCopy.Duration = fmt.Sprintf("%.1fs", time.Since(conn.StartTime).Seconds())
		connCopy.CancelFunc = nil
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
	var req struct {
		Target int `json:"target"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Target < 100 {
		http.Error(w, `{"error":"无效"}`, 400)
		return
	}
	if req.Target > maxPoolSize {
		req.Target = maxPoolSize
	}
	config.TargetPool = req.Target
	saveConfigToFile()
	if atomic.LoadInt64(&stats.PoolSize) < int64(config.TargetPool) {
		atomic.StoreInt32(&backgroundRunning, 1)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("已设置: %d", req.Target)})
}

func handleAPIRotate(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, `{"error":"POST only"}`, 405)
			return
		}
		go rotateIPPool(ctx)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "轮换中..."})
	}
}

func handleAPIAutoRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST only"}`, 405)
		return
	}
	var req struct {
		Enabled  bool `json:"enabled"`
		Interval int  `json:"interval"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, `{"error":"无效"}`, 400)
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
	json.NewEncoder(w).Encode(map[string]string{"message": "已更新"})
}

func handleAPIPortAdd(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, `{"error":"POST only"}`, 405)
			return
		}
		var req ProxyPort
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, `{"error":"无效"}`, 400)
			return
		}
		if req.Port == "" || req.Username == "" || req.Password == "" {
			http.Error(w, `{"error":"参数不完整"}`, 400)
			return
		}
		
		proxyPortsLock.Lock()
		if _, exists := proxyPorts[req.Port]; exists {
			proxyPortsLock.Unlock()
			http.Error(w, `{"error":"端口已存在"}`, 400)
			return
		}
		req.Enabled = true
		proxyPorts[req.Port] = &req
		config.ProxyPorts[req.Port] = &req
		proxyPortsLock.Unlock()
		
		if err := startProxyListener(ctx, req.Port); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"启动失败: %v"}`, err), 500)
			return
		}
		
		saveConfigToFile()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "已添加"})
	}
}

func handleAPIPortUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST only"}`, 405)
		return
	}
	var req ProxyPort
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, `{"error":"无效"}`, 400)
		return
	}
	
	proxyPortsLock.Lock()
	if port, exists := proxyPorts[req.Port]; exists {
		port.Username = req.Username
		port.Password = req.Password
		port.Enabled = req.Enabled
		config.ProxyPorts[req.Port] = port
	} else {
		proxyPortsLock.Unlock()
		http.Error(w, `{"error":"端口不存在"}`, 404)
		return
	}
	proxyPortsLock.Unlock()
	
	saveConfigToFile()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "已更新"})
}

func handleAPIPortDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST only"}`, 405)
		return
	}
	var req struct {
		Port string `json:"port"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, `{"error":"无效"}`, 400)
		return
	}
	
	listenersLock.Lock()
	if listener, exists := listeners[req.Port]; exists {
		listener.Close()
		delete(listeners, req.Port)
	}
	listenersLock.Unlock()
	
	proxyPortsLock.Lock()
	delete(proxyPorts, req.Port)
	delete(config.ProxyPorts, req.Port)
	proxyPortsLock.Unlock()
	
	saveConfigToFile()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "已删除"})
}

// v8.0 Final Plus 新增：进程管理 API
func handleAPIProcessList(w http.ResponseWriter, r *http.Request) {
	processes, err := getAllIPv6ProxyProcesses()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), 500)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":     len(processes),
		"max":       maxProcessCount,
		"processes": processes,
	})
}

func handleAPIProcessKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST only"}`, 405)
		return
	}
	
	var req struct {
		PID int32 `json:"pid"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, `{"error":"无效"}`, 400)
		return
	}
	
	if req.PID == int32(os.Getpid()) {
		http.Error(w, `{"error":"不能杀死当前进程"}`, 400)
		return
	}
	
	proc, err := os.FindProcess(int(req.PID))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"进程不存在: %v"}`, err), 404)
		return
	}
	
	if err := proc.Kill(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"杀死失败: %v"}`, err), 500)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("已杀死进程 %d", req.PID)})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile(indexHTMLPath)
	if err != nil {
		http.Error(w, "index.html not found", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(config.WebUsername)) != 1 || 
		   subtle.ConstantTimeCompare([]byte(pass), []byte(config.WebPassword)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized\n"))
			return
		}
		next(w, r)
	}
}

func startWebServer(ctx context.Context) *http.Server {
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
	mux.HandleFunc("/api/autorotate", basicAuth(handleAPIAutoRotate))
	mux.HandleFunc("/api/port/add", basicAuth(handleAPIPortAdd(ctx)))
	mux.HandleFunc("/api/port/update", basicAuth(handleAPIPortUpdate))
	mux.HandleFunc("/api/port/delete", basicAuth(handleAPIPortDelete))
	mux.HandleFunc("/api/processes", basicAuth(handleAPIProcessList))
	mux.HandleFunc("/api/process/kill", basicAuth(handleAPIProcessKill))
	
	srv := &http.Server{
		Addr:    ":" + config.WebPort,
		Handler: mux,
	}
	log.Printf("Web: http://0.0.0.0:%s", config.WebPort)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Web失败: %v", err)
		}
	}()
	return srv
}

func cleanupIPs() {
	poolLock.RLock()
	ipsToClean := make([]net.IP, len(ipv6Pool))
	copy(ipsToClean, ipv6Pool)
	poolLock.RUnlock()
	for _, ip := range ipsToClean {
		delIPv6(ip)
	}
}

func forceCloseAllConnections() {
	log.Printf("强制关闭所有连接...")
	activeConnectionsLock.Lock()
	for _, conn := range activeConnections {
		if conn.CancelFunc != nil {
			conn.CancelFunc()
		}
	}
	count := len(activeConnections)
	activeConnections = make(map[string]*ActiveConn)
	activeConnectionsLock.Unlock()
	
	listenersLock.Lock()
	for port, listener := range listeners {
		listener.Close()
		log.Printf("关闭端口: %s", port)
	}
	listenersLock.Unlock()
	
	log.Printf("已清理 %d 个连接", count)
}

func main() {
	mrand.Seed(time.Now().UnixNano())
	log.Printf("╔════════════════════════════════════════════╗")
	log.Printf("║ IPv6 代理 v8.0 Final Plus (终极版)    ║")
	log.Printf("╚════════════════════════════════════════════╝")

	stats.StartTime = time.Now()

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("无法获取路径: %v", err)
	}
	exeDir := filepath.Dir(exePath)
	configFilePath = filepath.Join(exeDir, "config.json")
	indexHTMLPath = filepath.Join(exeDir, "index.html")

	isInteractive := term.IsTerminal(int(syscall.Stdin))

	if isInteractive {
		if err := runInteractiveSetup(); err != nil {
			log.Fatalf("设置失败: %v", err)
		}
		if err := saveConfigToFile(); err != nil {
			log.Fatalf("保存失败: %v", err)
		}
	} else {
		if err := loadConfigFromFile(); err != nil {
			log.Fatalf("加载失败: %v", err)
		}
	}

	prefixIP, prefixNet, err = net.ParseCIDR(config.IPv6Prefix + "::/64")
	if err != nil {
		log.Fatalf("解析前缀失败: %v", err)
	}
	iface, err = netlink.LinkByName(config.Interface)
	if err != nil {
		log.Fatalf("找不到网卡: %v", err)
	}

	log.Printf("配置: Web:%s", config.WebPort)
	log.Printf("网络: %s::/64 @ %s", config.IPv6Prefix, config.Interface)
	log.Printf("IP池: %d → %d (最大 %d)", config.InitialPool, config.TargetPool, maxPoolSize)
	log.Printf("并发: 最大 %d 连接", maxConcurrentConns)
	log.Printf("超时: 5分钟强制关闭")
	log.Printf("进程: 最多 %d 个进程（自动清理）", maxProcessCount)
	if config.AutoRotate {
		log.Printf("轮换: 每 %d 小时", config.AutoRotateHours)
	}

	if err := initIPv6Pool(); err != nil {
		log.Fatalf("初始化失败: %v", err)
	}

	connectionSemaphore = make(chan struct{}, maxConcurrentConns)
	proxyPorts = make(map[string]*ProxyPort)
	listeners = make(map[string]net.Listener)

	for port, portConfig := range config.ProxyPorts {
		proxyPorts[port] = portConfig
	}

	ctx, cancel := context.WithCancel(context.Background())
	if config.TargetPool > config.InitialPool {
		atomic.StoreInt32(&backgroundRunning, 1)
	}
	
	discardQueue = make(chan net.IP, 5000)
	discardBatch = make([]net.IP, 0, batchDeleteSize)

	if config.AutoRotate {
		atomic.StoreInt32(&autoRotateEnabled, 1)
		atomic.StoreInt64(&autoRotateInterval, int64(config.AutoRotateHours))
		nextRotateTime = time.Now().Add(time.Duration(config.AutoRotateHours) * time.Hour)
	}

	go backgroundAddTask(ctx)
	go discardWorker(ctx)
	go statsRoutine(ctx)
	go statsCPURoutine(ctx)
	go statsHistoryRoutine(ctx)
	go logClearRoutine(ctx)
	go autoRotateRoutine(ctx)
	go zombieCleanupRoutine(ctx)
	go processManagerRoutine(ctx)  // v8.0 Final Plus 新增

	webServer := startWebServer(ctx)

	for port, portConfig := range proxyPorts {
		if portConfig.Enabled {
			if err := startProxyListener(ctx, port); err != nil {
				log.Fatalf("启动端口 %s 失败: %v", port, err)
			}
		}
	}

	log.Printf("✅ 服务就绪")

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)

	<-shutdownChan
	log.Printf("\n关闭中...")
	cancel()
	
	forceCloseAllConnections()
	webServer.Shutdown(context.Background())
	cleanupIPs()
	log.Printf("✅ 已关闭")
}
MAINEOF

echo "✅ Go 源代码完成（v8.0 Final Plus - 进程管理增强）"

# --- 继续创建 HTML 界面...
HTMLEOF

chmod +x /tmp/install-ipv6-proxy-v8.0-final-plus.sh
echo ""
echo "====================================================="
echo "✅ v8.0 Final Plus 安装脚本 Part 1 已创建"
echo "====================================================="
echo ""
echo "📝 接下来创建完整的 HTML 界面（包含进程管理面板）..."

# --- 创建完整 HTML 界面（包含进程管理）---
cat > "$BUILD_DIR/index.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IPv6 代理 v8.0 Final Plus</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {margin:0;padding:0;box-sizing:border-box}
        body {font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:10px}
        .container {max-width:1600px;margin:0 auto}
        h1 {font-size:24px;margin-bottom:20px;color:#60a5fa}
        .grid {display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:20px}
        @media (max-width:600px) {.grid {grid-template-columns:1fr} h1 {font-size:20px}}
        .card {background:#1e293b;border-radius:12px;padding:20px;cursor:pointer;transition:all .3s;position:relative}
        .card:hover {background:#334155;transform:translateY(-2px)}
        .card.clickable::after {content:'👆 点击查看';position:absolute;top:10px;right:15px;font-size:11px;color:#60a5fa;opacity:0.7}
        .card-title {font-size:13px;color:#94a3b8;margin-bottom:8px}
        .card-value {font-size:28px;font-weight:bold;color:#60a5fa}
        .card-value-small {font-size:20px;font-weight:bold;color:#60a5fa}
        .card-value-small .success {color:#10b981}
        .card-value-small .fail {color:#ef4444}
        .card-sub {font-size:12px;color:#64748b;margin-top:5px}
        .progress-bar {width:100%;height:8px;background:#334155;border-radius:4px;overflow:hidden;margin-top:10px}
        .progress-fill {height:100%;background:linear-gradient(90deg,#3b82f6,#60a5fa);transition:width .3s}
        .section {background:#1e293b;border-radius:12px;padding:20px;margin-bottom:20px;overflow:hidden}
        .section-title {font-size:18px;margin-bottom:15px;display:flex;align-items:center;gap:10px}
        .log-container {max-height:400px;overflow-y:auto;overflow-x:auto}
        table {width:100%;border-collapse:collapse;min-width:600px}
        th,td {padding:8px 10px;text-align:left;border-bottom:1px solid #334155;font-size:13px;white-space:nowrap}
        th {color:#94a3b8;font-size:12px;position:sticky;top:0;background:#1e293b}
        .status-success {color:#10b981}
        .status-fail {color:#ef4444}
        .status-timeout {color:#f59e0b}
        .input-group {display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:15px}
        input[type=number],input[type=text],input[type=password] {background:#334155;border:1px solid #475569;color:#e2e8f0;padding:8px 12px;border-radius:6px;min-width:120px}
        button {background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:14px;transition:all .3s}
        button:hover {background:#2563eb}
        button:disabled {background:#334155;cursor:not-allowed}
        button.warning {background:#f59e0b}
        button.warning:hover {background:#d97706}
        button.danger {background:#ef4444}
        button.danger:hover {background:#dc2626}
        button.success {background:#10b981}
        button.success:hover {background:#059669}
        button.small {padding:4px 8px;font-size:12px}
        .badge {display:inline-block;padding:4px 8px;border-radius:4px;font-size:12px}
        .badge-success {background:#10b98120;color:#10b981}
        .badge-info {background:#3b82f620;color:#3b82f6}
        .badge-warning {background:#f59e0b20;color:#f59e0b}
        .badge-danger {background:#ef444420;color:#ef4444}
        .chart-container {height:200px;margin-top:15px}
        canvas {max-height:200px}
        .modal {display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.7);align-items:center;justify-content:center}
        .modal.show {display:flex}
        .modal-content {background:#1e293b;border-radius:12px;padding:30px;max-width:600px;width:90%;max-height:80vh;overflow-y:auto}
        .modal-title {font-size:20px;color:#60a5fa;margin-bottom:20px}
        .form-group {margin-bottom:15px}
        .form-group label {display:block;color:#94a3b8;margin-bottom:5px;font-size:13px}
        .form-group input {width:100%;background:#334155;border:1px solid #475569;color:#e2e8f0;padding:10px;border-radius:6px}
        .form-actions {display:flex;gap:10px;margin-top:20px}
        .form-actions button {flex:1}
        .proxy-card {background:#334155;border-radius:8px;padding:15px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}
        .proxy-card-info {flex:1}
        .proxy-card-title {font-size:16px;color:#60a5fa;margin-bottom:5px}
        .proxy-card-subtitle {font-size:12px;color:#94a3b8}
        .proxy-card-actions {display:flex;gap:5px}
        .icon-btn {background:transparent;border:1px solid #475569;padding:6px 10px;font-size:12px}
        .icon-btn:hover {border-color:#60a5fa;background:#60a5fa20}
        .process-list {margin-top:15px}
        .process-item {background:#334155;border-radius:8px;padding:12px 15px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}
        .process-info {flex:1}
        .process-title {font-size:14px;color:#e2e8f0;margin-bottom:3px}
        .process-details {font-size:11px;color:#94a3b8}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
<div class="container">
    <h1>🚀 IPv6 代理 v8.0 Final Plus - 终极完整版</h1>
    
    <div class="grid">
        <div class="card"><div class="card-title">活跃连接</div><div class="card-value" id="active">-</div></div>
        <div class="card"><div class="card-title">总连接</div><div class="card-value" id="total">-</div><div class="card-sub">QPS: <span id="qps">-</span></div></div>
        <div class="card"><div class="card-title">统计</div><div class="card-value-small"><span class="success" id="success">-</span> / <span class="fail" id="failed">-</span></div><div class="card-sub">超时: <span id="timeout">-</span></div></div>
        <div class="card clickable" onclick="showProcessModal()"><div class="card-title">进程 CPU</div><div class="card-value" id="pcpu">- %</div><div class="card-sub">进程数: <span id="proc-count">-</span></div></div>
        <div class="card"><div class="card-title">系统 CPU</div><div class="card-value" id="scpu">- %</div></div>
        <div class="card"><div class="card-title">平均耗时</div><div class="card-value" id="avgdur">- ms</div></div>
        <div class="card"><div class="card-title">IPv6 池</div><div class="card-value" id="pool">-</div><div class="card-sub">目标: <span id="target">-</span></div><div class="progress-bar"><div class="progress-fill" id="prog"></div></div></div>
        <div class="card"><div class="card-title">运行时间</div><div class="card-value" id="uptime" style="font-size:20px">-</div></div>
    </div>

    <div class="section">
        <div class="section-title">🔌 代理端口管理 <button class="success" style="margin-left:auto" onclick="showAddPortModal()">+ 新增端口</button></div>
        <div id="portsList"></div>
    </div>

    <div class="section"><div class="section-title">📊 性能图表</div><div class="chart-container"><canvas id="chart"></canvas></div></div>
    
    <div class="section">
        <div class="section-title">📊 IP 池管理</div>
        <div class="input-group">
            <label>目标池大小:</label>
            <input type="number" id="tgt" placeholder="30000" min="100" step="1000">
            <button onclick="resize()">应用</button>
            <span id="pst"></span>
            <button class="warning" onclick="rotate()">立即轮换</button>
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">👥 实时连接 <span class="badge badge-info" id="acnt">0</span></div>
        <div class="log-container">
            <table>
                <thead><tr><th>客户端</th><th>目标</th><th>IPv6</th><th>端口</th><th>时长</th></tr></thead>
                <tbody id="atbl"><tr><td colspan="5" style="text-align:center;color:#64748b">无</td></tr></tbody>
            </table>
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">🔍 搜索日志</div>
        <div class="input-group">
            <input type="text" id="sq" placeholder="搜索 IP、目标..." style="flex:1">
            <button onclick="search()">搜索</button>
            <button onclick="clearSearch()">清除</button>
            <span id="scnt"></span>
        </div>
        <div class="log-container" id="scon" style="display:none">
            <table>
                <thead><tr><th>时间</th><th>客户端</th><th>目标</th><th>IPv6</th><th>端口</th><th>状态</th><th>耗时</th></tr></thead>
                <tbody id="stbl"></tbody>
            </table>
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">📝 最近连接</div>
        <div class="log-container">
            <table>
                <thead><tr><th>时间</th><th>客户端</th><th>目标</th><th>IPv6</th><th>端口</th><th>状态</th><th>耗时</th></tr></thead>
                <tbody id="ltbl"><tr><td colspan="7" style="text-align:center;color:#64748b">等待...</td></tr></tbody>
            </table>
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">❌ 失败日志</div>
        <div class="log-container">
            <table>
                <thead><tr><th>时间</th><th>客户端</th><th>目标</th><th>IPv6</th><th>端口</th><th>状态</th><th>耗时</th></tr></thead>
                <tbody id="ftbl"><tr><td colspan="7" style="text-align:center;color:#64748b">无</td></tr></tbody>
            </table>
        </div>
    </div>
</div>

<!-- 新增端口弹窗 -->
<div id="addPortModal" class="modal">
    <div class="modal-content">
        <div class="modal-title">🔌 新增代理端口</div>
        <div class="form-group">
            <label>端口号</label>
            <input type="text" id="newPort" placeholder="例如: 1081">
        </div>
        <div class="form-group">
            <label>用户名</label>
            <input type="text" id="newUsername" placeholder="proxy">
        </div>
        <div class="form-group">
            <label>密码</label>
            <input type="password" id="newPassword" placeholder="密码">
        </div>
        <div class="form-actions">
            <button class="success" onclick="addPort()">添加</button>
            <button onclick="closeModal('addPortModal')">取消</button>
        </div>
    </div>
</div>

<!-- 编辑端口弹窗 -->
<div id="editPortModal" class="modal">
    <div class="modal-content">
        <div class="modal-title">✏️ 编辑端口配置</div>
        <input type="hidden" id="editPort">
        <div class="form-group">
            <label>用户名</label>
            <input type="text" id="editUsername" placeholder="proxy">
        </div>
        <div class="form-group">
            <label>密码</label>
            <input type="password" id="editPassword" placeholder="密码">
        </div>
        <div class="form-actions">
            <button class="success" onclick="updatePort()">保存</button>
            <button onclick="closeModal('editPortModal')">取消</button>
        </div>
    </div>
</div>

<!-- 进程管理弹窗 -->
<div id="processModal" class="modal">
    <div class="modal-content">
        <div class="modal-title">⚙️ 进程管理</div>
        <div style="margin-bottom:15px;padding:12px;background:#334155;border-radius:6px">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <div>
                    <div style="font-size:14px;color:#e2e8f0">当前运行: <strong id="proc-modal-count">-</strong> 个进程</div>
                    <div style="font-size:12px;color:#94a3b8;margin-top:3px">最大允许: <strong>5</strong> 个（超过自动清理）</div>
                </div>
                <button class="success small" onclick="refreshProcesses()">🔄 刷新</button>
            </div>
        </div>
        <div class="process-list" id="processList"></div>
        <div class="form-actions" style="margin-top:20px">
            <button onclick="closeModal('processModal')">关闭</button>
        </div>
    </div>
</div>

<script>
let chart;
let currentPorts = [];

function initChart(){
    const ctx=document.getElementById('chart').getContext('2d');
    chart=new Chart(ctx,{
        type:'line',
        data:{
            labels:[],
            datasets:[
                {label:'QPS',data:[],borderColor:'#3b82f6',yAxisID:'y',tension:0.4},
                {label:'成功率%',data:[],borderColor:'#10b981',yAxisID:'y1',tension:0.4},
                {label:'CPU%',data:[],borderColor:'#f59e0b',yAxisID:'y1',tension:0.4}
            ]
        },
        options:{
            responsive:true,
            maintainAspectRatio:false,
            plugins:{legend:{labels:{color:'#e2e8f0'}}},
            scales:{
                x:{ticks:{color:'#94a3b8'},grid:{color:'#334155'}},
                y:{type:'linear',position:'left',ticks:{color:'#94a3b8'},grid:{color:'#334155'}},
                y1:{type:'linear',position:'right',ticks:{color:'#94a3b8'},grid:{display:false}}
            }
        }
    });
}

async function updateStats(){
    try{
        const d=await fetch('/api/stats').then(r=>r.json());
        document.getElementById('active').textContent=d.active;
        document.getElementById('total').textContent=d.total;
        document.getElementById('qps').textContent=d.qps.toFixed(2);
        document.getElementById('success').textContent=d.success;
        document.getElementById('failed').textContent=d.failed;
        document.getElementById('timeout').textContent=d.timeout;
        document.getElementById('pcpu').textContent=d.process_cpu.toFixed(1)+' %';
        document.getElementById('scpu').textContent=d.system_cpu.toFixed(1)+' %';
        document.getElementById('avgdur').textContent=d.avg_duration.toFixed(0)+' ms';
        document.getElementById('pool').textContent=d.pool;
        document.getElementById('target').textContent=d.target;
        document.getElementById('prog').style.width=d.progress.toFixed(1)+'%';
        document.getElementById('uptime').textContent=d.uptime;
        document.getElementById('pst').innerHTML=d.bg_running?'<span class="badge badge-info">运行中</span>':'<span class="badge badge-success">就绪</span>';
        
        if(d.proxy_ports){
            currentPorts=d.proxy_ports;
            renderPorts();
        }
    }catch(e){}
}

async function updateProcessCount(){
    try{
        const d=await fetch('/api/processes').then(r=>r.json());
        const count=d.count||0;
        const max=d.max||5;
        let badge='';
        if(count>max){
            badge='<span class="badge badge-danger">'+count+'</span>';
        }else if(count>=max-1){
            badge='<span class="badge badge-warning">'+count+'</span>';
        }else{
            badge='<span class="badge badge-success">'+count+'</span>';
        }
        document.getElementById('proc-count').innerHTML=badge;
    }catch(e){}
}

function renderPorts(){
    const container=document.getElementById('portsList');
    if(currentPorts.length===0){
        container.innerHTML='<p style="text-align:center;color:#64748b;padding:20px">暂无端口</p>';
        return;
    }
    container.innerHTML=currentPorts.map(p=>`
        <div class="proxy-card">
            <div class="proxy-card-info">
                <div class="proxy-card-title">端口 ${p.port}</div>
                <div class="proxy-card-subtitle">用户: ${p.username} ${p.enabled?'<span class="badge badge-success">启用</span>':'<span class="badge badge-warning">禁用</span>'}</div>
            </div>
            <div class="proxy-card-actions">
                <button class="icon-btn" onclick="showEditPortModal('${p.port}','${p.username}')">✏️ 编辑</button>
                <button class="icon-btn danger" onclick="deletePort('${p.port}')">🗑️ 删除</button>
            </div>
        </div>
    `).join('');
}

function showAddPortModal(){
    document.getElementById('newPort').value='';
    document.getElementById('newUsername').value='';
    document.getElementById('newPassword').value='';
    document.getElementById('addPortModal').classList.add('show');
}

function showEditPortModal(port,username){
    document.getElementById('editPort').value=port;
    document.getElementById('editUsername').value=username;
    document.getElementById('editPassword').value='';
    document.getElementById('editPortModal').classList.add('show');
}

async function showProcessModal(){
    document.getElementById('processModal').classList.add('show');
    await refreshProcesses();
}

async function refreshProcesses(){
    try{
        const d=await fetch('/api/processes').then(r=>r.json());
        document.getElementById('proc-modal-count').textContent=d.count||0;
        
        const container=document.getElementById('processList');
        if(!d.processes||d.processes.length===0){
            container.innerHTML='<p style="text-align:center;color:#64748b;padding:20px">无运行中的进程</p>';
            return;
        }
        
        container.innerHTML=d.processes.map(p=>`
            <div class="process-item">
                <div class="process-info">
                    <div class="process-title">PID: ${p.pid}</div>
                    <div class="process-details">
                        运行时长: ${p.uptime} | CPU: ${p.cpu_percent.toFixed(1)}% | 内存: ${p.memory_mb.toFixed(0)} MB
                    </div>
                </div>
                <button class="danger small" onclick="killProcess(${p.pid})" ${p.pid==currentPID?'disabled':''}>
                    ${p.pid==currentPID?'当前进程':'🗑️ 杀死'}
                </button>
            </div>
        `).join('');
    }catch(e){
        alert('获取进程列表失败');
    }
}

async function killProcess(pid){
    if(!confirm(`确定要杀死进程 PID=${pid} 吗？`))return;
    
    try{
        const r=await fetch('/api/process/kill',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({pid:pid})
        }).then(r=>r.json());
        alert(r.message||'已杀死进程');
        await refreshProcesses();
        updateProcessCount();
    }catch(e){
        alert('操作失败: '+e.message);
    }
}

function closeModal(id){
    document.getElementById(id).classList.remove('show');
}

async function addPort(){
    const port=document.getElementById('newPort').value.trim();
    const username=document.getElementById('newUsername').value.trim();
    const password=document.getElementById('newPassword').value;
    
    if(!port||!username||!password){
        alert('请填写完整信息');
        return;
    }
    
    try{
        const r=await fetch('/api/port/add',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({port,username,password})
        }).then(r=>r.json());
        alert(r.message||'已添加');
        closeModal('addPortModal');
        updateStats();
    }catch(e){
        alert('操作失败: '+e.message);
    }
}

async function updatePort(){
    const port=document.getElementById('editPort').value;
    const username=document.getElementById('editUsername').value.trim();
    const password=document.getElementById('editPassword').value;
    
    if(!username){
        alert('用户名不能为空');
        return;
    }
    
    const data={port,username,enabled:true};
    if(password)data.password=password;
    
    try{
        const r=await fetch('/api/port/update',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify(data)
        }).then(r=>r.json());
        alert(r.message||'已更新');
        closeModal('editPortModal');
        updateStats();
    }catch(e){
        alert('操作失败: '+e.message);
    }
}

async function deletePort(port){
    if(!confirm(`确定删除端口 ${port} 吗？`))return;
    
    try{
        const r=await fetch('/api/port/delete',{
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({port})
        }).then(r=>r.json());
        alert(r.message||'已删除');
        updateStats();
    }catch(e){
        alert('操作失败: '+e.message);
    }
}

async function updateChart(){
    try{
        const h=await fetch('/api/history').then(r=>r.json());
        if(h.length===0)return;
        chart.data.labels=h.map(x=>x.timestamp);
        chart.data.datasets[0].data=h.map(x=>x.qps);
        chart.data.datasets[1].data=h.map(x=>x.success_rate);
        chart.data.datasets[2].data=h.map(x=>x.process_cpu);
        chart.update('none');
    }catch(e){}
}

function renderTable(tid,logs,msg,cols){
    const t=document.getElementById(tid);
    if(!logs||logs.length===0){
        t.innerHTML=`<tr><td colspan="${cols}" style="text-align:center;color:#64748b">${msg}</td></tr>`;
        return;
    }
    t.innerHTML=logs.map(l=>{
        let c=l.status.includes('✅')?'status-success':l.status.includes('⏱')?'status-timeout':'status-fail';
        return`<tr><td>${l.time}</td><td>${l.client_ip}</td><td>${l.target}</td><td>${l.ipv6}</td><td>${l.port||'-'}</td><td class="${c}">${l.status}</td><td>${l.duration}</td></tr>`;
    }).join('');
}

async function updateLogs(){
    try{
        const l=await fetch('/api/logs').then(r=>r.json());
        renderTable('ltbl',l,'等待...',7);
    }catch(e){}
}

async function updateFailLogs(){
    try{
        const l=await fetch('/api/faillogs').then(r=>r.json());
        renderTable('ftbl',l,'无',7);
    }catch(e){}
}

async function updateActive(){
    try{
        const c=await fetch('/api/active').then(r=>r.json());
        document.getElementById('acnt').textContent=c.length;
        const t=document.getElementById('atbl');
        if(c.length===0){
            t.innerHTML='<tr><td colspan="5" style="text-align:center;color:#64748b">无</td></tr>';
            return;
        }
        t.innerHTML=c.map(x=>`<tr><td>${x.client_ip}</td><td>${x.target}</td><td>${x.ipv6}</td><td>${x.port||'-'}</td><td>${x.duration}</td></tr>`).join('');
    }catch(e){}
}

async function search(){
    const q=document.getElementById('sq').value.trim();
    if(!q){alert('请输入关键词');return}
    try{
        const r=await fetch(`/api/search?q=${encodeURIComponent(q)}`).then(r=>r.json());
        document.getElementById('scnt').textContent=`找到 ${r.length} 条`;
        document.getElementById('scon').style.display='block';
        renderTable('stbl',r,'未找到',7);
    }catch(e){alert('搜索失败')}
}

function clearSearch(){
    document.getElementById('sq').value='';
    document.getElementById('scnt').textContent='';
    document.getElementById('scon').style.display='none';
}

async function resize(){
    const t=parseInt(document.getElementById('tgt').value);
    if(!t||t<100){alert('无效值');return}
    try{
        const r=await fetch('/api/pool/resize',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:t})}).then(r=>r.json());
        alert(r.message);
        updateStats();
    }catch(e){alert('操作失败')}
}

async function rotate(){
    if(!confirm('确定立即轮换 IP 池吗？'))return;
    try{
        const r=await fetch('/api/rotate',{method:'POST'}).then(r=>r.json());
        alert(r.message);
        updateStats();
    }catch(e){alert('操作失败')}
}

document.getElementById('sq').addEventListener('keypress',(e)=>{if(e.key==='Enter')search()});
document.querySelectorAll('.modal').forEach(m=>m.addEventListener('click',(e)=>{if(e.target===m)closeModal(m.id)}));

// 获取当前进程 PID（用于禁用杀死当前进程的按钮）
let currentPID = null;
fetch('/api/processes').then(r=>r.json()).then(d=>{
    if(d.processes&&d.processes.length>0){
        currentPID=d.processes[d.processes.length-1].pid; // 最新的进程是当前进程
    }
});

initChart();
setInterval(updateStats,3000);
setInterval(updateChart,5000);
setInterval(updateLogs,5000);
setInterval(updateFailLogs,5000);
setInterval(updateActive,3000);
setInterval(updateProcessCount,5000);
updateStats();
updateChart();
updateLogs();
updateFailLogs();
updateActive();
updateProcessCount();
</script>
</body>
</html>
HTMLEOF

echo "✅ HTML 界面完成（包含进程管理面板）"

# --- 编译 ---
echo "--- 步骤 5: 编译 Go 程序 ---"
cd "$BUILD_DIR"
/usr/local/go/bin/go mod init ipv6-proxy >/dev/null 2>&1
/usr/local/go/bin/go mod tidy >/dev/null
CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags "-s -w" -o ipv6-proxy .
echo "✅ 编译完成"

# --- 安装 ---
echo "--- 步骤 6: 安装到系统 ---"
mkdir -p "$INSTALL_DIR"
mv ipv6-proxy "$INSTALL_DIR/"
mv index.html "$INSTALL_DIR/"
cd /
rm -rf "$BUILD_DIR"
echo "✅ 安装完成"

# --- systemd 服务 ---
echo "--- 步骤 7: 创建 systemd 服务 ---"
cat > /etc/systemd/system/ipv6-proxy.service << SERVICEEOF
[Unit]
Description=IPv6 Proxy v8.0 Final Plus
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/ipv6-proxy
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
Restart=always
RestartSec=5
LimitNOFILE=1000000
KillMode=mixed
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
echo "✅ 服务创建完成"

# --- NDP 定期清理脚本 ---
echo "--- 步骤 8: NDP 定期清理 ---"
cat > /usr/local/bin/ndp-cleanup.sh << 'CLEANUPEOF'
#!/bin/bash
# NDP 表定期清理脚本
IFACE=$(ip -6 route | grep default | awk '{print $5}' | head -1)
if [ -n "$IFACE" ]; then
    ip -6 neigh flush dev $IFACE 2>/dev/null || true
fi
CLEANUPEOF

chmod +x /usr/local/bin/ndp-cleanup.sh

# 添加 cron 任务（每小时清理一次）
if ! crontab -l 2>/dev/null | grep -q "ndp-cleanup.sh"; then
    (crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/ndp-cleanup.sh >/dev/null 2>&1") | crontab -
fi
echo "✅ NDP 自动清理已设置"

# --- 启动服务 ---
echo "--- 步骤 9: 启动服务 ---"
systemctl enable ipv6-proxy.service
systemctl start ipv6-proxy.service
sleep 3
systemctl status ipv6-proxy.service --no-pager

echo ""
echo "============================================="
echo "=== ✅ IPv6 代理 v8.0 Final Plus 安装完成 ==="
echo "============================================="
echo ""
echo "📌 服务状态:"
echo "   systemctl status ipv6-proxy"
echo ""
echo "📌 查看日志:"
echo "   journalctl -u ipv6-proxy -f"
echo ""
echo "📌 配置文件:"
echo "   $INSTALL_DIR/config.json"
echo ""
echo "📌 Web 管理面板:"
echo "   http://$(hostname -I | awk '{print $1}'):8080"
echo "   (默认账号: admin / admin123)"
echo ""
echo "🎉 新增功能:"
echo "   🔥 自动清理多余进程（>5个自动杀最旧的）"
echo "   🔥 进程管理面板（点击CPU卡片查看）"
echo "   🔥 手动杀死进程按钮"
echo ""
echo "✅ 完整功能:"
echo "   🎨 卡片式配置界面"
echo "   🔌 多端口动态管理"
echo "   ⚡ 5分钟强制超时"
echo "   ✅ 完整泄漏修复"
echo "   ✅ 无锁随机优化"
echo "   ✅ 批量删除优化"
echo "   ✅ NDP 自动清理"
echo "   ✅ 僵尸连接清理（每2分钟）"
echo "   ✅ 并发限制 2000"
echo ""
echo "============================================="
