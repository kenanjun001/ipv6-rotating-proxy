#!/bin/bash
set -e

INSTALL_DIR="/opt/ipv6-proxy"
BUILD_DIR="/root/ipv6-proxy-build"
GO_VERSION="1.21.5"

if [ "$(id -u)" -ne 0 ]; then
  echo "❌ 需要 root 权限"
  exit 1
fi

echo "============================================="
echo "=== IPv6 代理 v8.0 Final Plus 安装 ==="
echo "============================================="

# 清理
systemctl stop ipv6-proxy.service 2>/dev/null || true
killall -9 ipv6-proxy 2>/dev/null || true
sleep 2
rm -rf /opt/ipv6-proxy* "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# 系统优化
cat > /etc/sysctl.d/99-ipv6-proxy.conf << 'SYSCTL'
net.ipv6.neigh.default.gc_thresh1 = 2048
net.ipv6.neigh.default.gc_thresh2 = 4096
net.ipv6.neigh.default.gc_thresh3 = 8192
net.ipv6.neigh.default.gc_stale_time = 60
net.netfilter.nf_conntrack_max = 1000000
net.core.somaxconn = 8192
fs.file-max = 1000000
SYSCTL
sysctl -p /etc/sysctl.d/99-ipv6-proxy.conf >/dev/null 2>&1

# 安装 Go
export GOROOT=/usr/local/go
export PATH=/usr/local/go/bin:$PATH
if [ ! -d "/usr/local/go" ]; then
  apt-get update -qq
  apt-get install -y wget -qq
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  tar -C /usr/local -xzf /tmp/go.tar.gz
  rm /tmp/go.tar.gz
fi
echo "✅ Go $(go version | awk '{print $3}')"

cd "$BUILD_DIR"

# 创建完整的 Go 源代码
echo "创建源代码..."

# 使用 base64 编码来避免 heredoc 问题
cat > create_source.sh << 'CREATOR'
#!/bin/bash
cd "$1"

# 主程序代码
cat > main.go << 'GOCODE'
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
	maxProcessCount     = 5
	processCheckInterval = 1 * time.Minute
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
				toKill := len(processes) - maxProcessCount
				for i := 0; i < toKill; i++ {
					pid := processes[i].PID
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
	log.Printf("IPv6 代理 v8.0 Final Plus")

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

	log.Printf("配置: Web:%s 网络:%s::/64@%s IP池:%d→%d",
		config.WebPort, config.IPv6Prefix, config.Interface, 
		config.InitialPool, config.TargetPool)

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
	go processManagerRoutine(ctx)

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
	log.Printf("关闭中...")
	cancel()
	
	forceCloseAllConnections()
	webServer.Shutdown(context.Background())
	cleanupIPs()
	log.Printf("✅ 已关闭")
}
GOCODE
CREATOR

bash create_source.sh "$BUILD_DIR"
rm -f create_source.sh

echo "✅ Go 源代码创建完成"

# 编译
echo "编译中..."
cd "$BUILD_DIR"
/usr/local/go/bin/go mod init ipv6-proxy 2>&1 | grep -v "go: creating"
/usr/local/go/bin/go mod tidy 2>&1 | tail -5
CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags "-s -w" -o ipv6-proxy . 2>&1 | grep -v "go: downloading" || true

if [ ! -f "ipv6-proxy" ]; then
  echo "❌ 编译失败，查看详细日志:"
  CGO_ENABLED=0 /usr/local/go/bin/go build -v -o ipv6-proxy .
  exit 1
fi
echo "✅ 编译成功"

# 创建 HTML
echo "创建 Web 界面..."
wget -q https://pastebin.com/raw/ipv6proxy-html -O index.html 2>/dev/null || cat > index.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>IPv6 Proxy v8.0</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px}
.container{max-width:1400px;margin:0 auto}
h1{font-size:28px;margin-bottom:30px;color:#60a5fa}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;margin-bottom:30px}
.card{background:#1e293b;border-radius:12px;padding:25px;transition:transform .2s}
.card:hover{transform:translateY(-2px)}
.card-title{font-size:14px;color:#94a3b8;margin-bottom:10px}
.card-value{font-size:32px;font-weight:bold;color:#60a5fa}
.card-sub{font-size:13px;color:#64748b;margin-top:8px}
button{background:#3b82f6;color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:14px;transition:all .3s}
button:hover{background:#2563eb}
button.danger{background:#ef4444}
button.danger:hover{background:#dc2626}
.section{background:#1e293b;border-radius:12px;padding:25px;margin-bottom:20px}
.section-title{font-size:20px;margin-bottom:20px;color:#e2e8f0}
.process-list{margin-top:15px}
.process-item{background:#334155;border-radius:8px;padding:15px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.process-info{flex:1}
.process-title{font-size:15px;color:#e2e8f0;margin-bottom:5px}
.process-details{font-size:12px;color:#94a3b8}
.badge{display:inline-block;padding:4px 10px;border-radius:6px;font-size:12px;font-weight:600}
.badge-success{background:#10b98120;color:#10b981}
.badge-warning{background:#f59e0b20;color:#f59e0b}
.badge-danger{background:#ef444420;color:#ef4444}
</style>
</head>
<body>
<div class="container">
<h1>🚀 IPv6 代理 v8.0 Final Plus</h1>

<div class="grid">
<div class="card">
<div class="card-title">活跃连接</div>
<div class="card-value" id="active">-</div>
</div>
<div class="card">
<div class="card-title">总连接数</div>
<div class="card-value" id="total">-</div>
<div class="card-sub">QPS: <span id="qps">-</span></div>
</div>
<div class="card">
<div class="card-title">IPv6 池</div>
<div class="card-value" id="pool">-</div>
<div class="card-sub">目标: <span id="target">-</span></div>
</div>
<div class="card">
<div class="card-title">进程 CPU</div>
<div class="card-value" id="cpu">-</div>
<div class="card-sub">进程数: <span id="proc-badge"></span></div>
</div>
</div>

<div class="section">
<div class="section-title">⚙️ 进程管理 <button onclick="refreshProc()" style="float:right;font-size:13px">🔄 刷新</button></div>
<div id="proc-list"></div>
</div>

</div>

<script>
let currentPID=null;

async function update(){
try{
const d=await fetch('/api/stats').then(r=>r.json());
document.getElementById('active').textContent=d.active;
document.getElementById('total').textContent=d.total;
document.getElementById('qps').textContent=d.qps.toFixed(2);
document.getElementById('pool').textContent=d.pool;
document.getElementById('target').textContent=d.target;
document.getElementById('cpu').textContent=d.process_cpu.toFixed(1)+'%';

const p=await fetch('/api/processes').then(r=>r.json());
const cnt=p.count||0;
const max=p.max||5;
let badge=`<span class="badge badge-success">${cnt}</span>`;
if(cnt>=max)badge=`<span class="badge badge-danger">${cnt}</span>`;
else if(cnt>=max-1)badge=`<span class="badge badge-warning">${cnt}</span>`;
document.getElementById('proc-badge').innerHTML=badge;

if(p.processes&&p.processes.length>0){
currentPID=p.processes[p.processes.length-1].pid;
renderProc(p.processes);
}
}catch(e){}
}

function renderProc(procs){
const list=document.getElementById('proc-list');
if(!procs||procs.length===0){
list.innerHTML='<p style="text-align:center;color:#64748b;padding:20px">无运行中的进程</p>';
return;
}
list.innerHTML=procs.map(p=>`
<div class="process-item">
<div class="process-info">
<div class="process-title">PID: ${p.pid}</div>
<div class="process-details">运行时长: ${p.uptime} | CPU: ${p.cpu_percent.toFixed(1)}% | 内存: ${p.memory_mb.toFixed(0)} MB</div>
</div>
${p.pid===currentPID?'<button disabled>当前进程</button>':`<button class="danger" onclick="killProc(${p.pid})">🗑️ 杀死</button>`}
</div>
`).join('');
}

async function refreshProc(){
try{
const p=await fetch('/api/processes').then(r=>r.json());
if(p.processes)renderProc(p.processes);
}catch(e){alert('刷新失败')}
}

async function killProc(pid){
if(!confirm(`确定要杀死进程 PID=${pid} 吗？`))return;
try{
await fetch('/api/process/kill',{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({pid})
});
alert('已杀死进程');
refreshProc();
}catch(e){alert('操作失败')};
}

setInterval(update,5000);
update();
</script>
</body>
</html>
HTMLEOF
echo "✅ Web 界面创建完成"

# 安装
mkdir -p "$INSTALL_DIR"
mv ipv6-proxy index.html "$INSTALL_DIR/"
cd /
rm -rf "$BUILD_DIR"
echo "✅ 安装到 $INSTALL_DIR"

# systemd 服务
cat > /etc/systemd/system/ipv6-proxy.service << 'SERVICEEOF'
[Unit]
Description=IPv6 Proxy v8.0 Final Plus
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ipv6-proxy
ExecStart=/opt/ipv6-proxy/ipv6-proxy
Restart=always
RestartSec=5
LimitNOFILE=1000000
KillMode=mixed
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable ipv6-proxy.service
systemctl start ipv6-proxy.service
sleep 3

echo ""
echo "============================================="
echo "===        ✅ 安装完成！              ==="
echo "============================================="
echo ""
echo "📌 Web 管理:"
echo "   http://$(hostname -I | awk '{print $1}'):8080"
echo "   账号: admin / admin123"
echo ""
echo "📌 服务管理:"
echo "   状态: systemctl status ipv6-proxy"
echo "   日志: journalctl -u ipv6-proxy -f"
echo "   重启: systemctl restart ipv6-proxy"
echo ""
echo "🎉 功能特性:"
echo "   ✅ 自动进程管理（最多5个）"
echo "   ✅ 手动杀死进程"
echo "   ✅ 5分钟连接超时"
echo "   ✅ 完整泄漏修复"
echo "   ✅ 多端口支持"
echo ""
