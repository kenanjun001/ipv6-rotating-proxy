#!/bin/bash
#
# IPv6 代理 v7.4 Final 完全集成版安装脚本
# 包含：自动处理dpkg锁、错误恢复、界面优化
#

INSTALL_DIR="/opt/ipv6-proxy"
BUILD_DIR="/root/ipv6-proxy-build"
GO_VERSION="1.21.5"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=/usr/local/go/bin:$PATH:$GOPATH/bin

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 不在出错时退出，我们要处理错误
set +e

# 打印函数
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }

# 检查root权限
if [ "$(id -u)" -ne 0 ]; then
    print_error "需要 root 权限"
    echo "请使用: sudo $0"
    exit 1
fi

echo "============================================="
echo "=== IPv6 代理 v7.4 Final 完全集成版 ==="
echo "============================================="
echo ""

# --- 智能处理dpkg锁 ---
handle_apt_locks() {
    local max_wait=60  # 最多等待60秒
    local waited=0
    local need_wait=false
    
    # 检查是否有锁
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
       fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
       fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
        need_wait=true
    fi
    
    if [ "$need_wait" = true ]; then
        print_warning "检测到系统正在进行其他操作"
        echo "正在智能处理..."
        
        # 首先尝试温和等待
        while [ $waited -lt $max_wait ]; do
            if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && \
               ! fuser /var/lib/dpkg/lock >/dev/null 2>&1 && \
               ! fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
                print_success "系统锁已释放"
                return 0
            fi
            
            if [ $((waited % 10)) -eq 0 ] && [ $waited -gt 0 ]; then
                echo "   等待中... ($waited/$max_wait 秒)"
            fi
            
            sleep 2
            waited=$((waited + 2))
        done
        
        # 超时后强制处理
        print_info "自动清理系统锁..."
        
        # 停止相关进程
        killall apt 2>/dev/null || true
        killall apt-get 2>/dev/null || true
        killall dpkg 2>/dev/null || true
        killall unattended-upgr 2>/dev/null || true
        
        sleep 2
        
        # 清理锁文件
        rm -f /var/lib/apt/lists/lock
        rm -f /var/cache/apt/archives/lock
        rm -f /var/lib/dpkg/lock*
        rm -f /var/lib/dpkg/lock-frontend
        
        # 修复dpkg
        dpkg --configure -a 2>/dev/null || true
        
        print_success "系统锁已清理"
    fi
}

# --- 步骤 1: 清理旧版本 ---
echo "--- 步骤 1: 清理旧版本 ---"
systemctl stop ipv6-proxy.service >/dev/null 2>&1 || true
systemctl disable ipv6-proxy.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/ipv6-proxy.service
rm -rf /opt/ipv6-proxy
rm -rf "$BUILD_DIR"
systemctl daemon-reload
print_success "清理完成"
echo ""

# --- 步骤 2: 安装依赖 ---
echo "--- 步骤 2: 安装依赖 ---"

# 处理dpkg锁
handle_apt_locks

# 尝试更新apt
echo "更新软件包列表..."
for i in {1..3}; do
    if apt-get update >/dev/null 2>&1; then
        break
    else
        if [ $i -eq 3 ]; then
            print_warning "apt update 失败，尝试修复..."
            handle_apt_locks
            apt-get update --fix-missing >/dev/null 2>&1 || true
        else
            sleep 2
        fi
    fi
done

# 安装wget
echo "安装必要组件..."
for i in {1..3}; do
    if apt-get install -y wget >/dev/null 2>&1; then
        break
    else
        if [ $i -eq 3 ]; then
            print_error "安装 wget 失败"
            handle_apt_locks
            apt-get install -y wget --fix-missing >/dev/null 2>&1 || {
                print_error "无法安装依赖，请检查网络"
                exit 1
            }
        else
            sleep 2
        fi
    fi
done

# 清理旧版go
apt-get remove -y golang-go >/dev/null 2>&1 || true

# 安装Go
if [ ! -d "/usr/local/go" ] || ! /usr/local/go/bin/go version | grep -q "$GO_VERSION"; then
    echo "下载 Go $GO_VERSION..."
    wget -q "$GO_URL" -O "/tmp/$GO_TAR" || {
        print_error "下载 Go 失败，请检查网络"
        exit 1
    }
    tar -C /usr/local -xzf "/tmp/$GO_TAR"
    rm "/tmp/$GO_TAR"
fi

print_success "Go 环境就绪"
echo ""

# --- 步骤 3: 创建源代码 ---
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
	choice := readUserChoice(len(validPrefixes))
	return validPrefixes[choice-1], nil
}

func runInteractiveSetup() error {
	log.Println("--- Web 设置 ---")
	config.WebUsername = readUserString("Web账号", "admin")
	config.WebPassword = readUserPassword("Web密码", "admin123")
	
	log.Println("\n--- 代理设置 ---")
	config.Port = readUserString("代理端口", "1080")
	config.WebPort = readUserString("Web端口", "8080")
	config.Username = readUserString("代理用户名", "proxy")
	config.Password = readUserPassword("代理密码", "proxy123")

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
	
	return nil
}

func saveConfigToFile() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
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

func addConnLog(clientIP, target, ipv6, status string, duration time.Duration) {
	connLog := &ConnLog{
		Time:     time.Now().Format("15:04:05"),
		ClientIP: clientIP,
		Target:   target,
		IPv6:     ipv6,
		Status:   status,
		Duration: fmt.Sprintf("%.2fs", duration.Seconds()),
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
			fmt.Printf("\r   进度: %d/%d ", i+1, numToAdd)
		}
	}
	if term.IsTerminal(int(syscall.Stdin)) && numToAdd > 0 {
		fmt.Println()
	}
	return newIPs, success
}

func initIPv6Pool() error {
	log.Printf("初始化: %d 个IP", config.InitialPool)
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
	return user == config.Username && pass == config.Password
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
				log.Printf("自动轮换...")
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
		http.Error(w, `{"error":"缺少搜索关键词"}`, http.StatusBadRequest)
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
			strings.Contains(strings.ToLower(log.Status), query) {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"无效请求"}`, http.StatusBadRequest)
		return
	}

	if req.Target < 100 {
		http.Error(w, `{"error":"目标值至少100"}`, http.StatusBadRequest)
		return
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
			http.Error(w, `{"error":"仅支持POST"}`, http.StatusMethodNotAllowed)
			return
		}
		
		go rotateIPPool(ctx)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "轮换已开始"})
	}
}

func handleAPIUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"仅支持POST"}`, http.StatusMethodNotAllowed)
		return
	}

	var newConfig Config
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, `{"error":"无效配置"}`, http.StatusBadRequest)
		return
	}

	newConfig.IPv6Prefix = config.IPv6Prefix
	newConfig.Interface = config.Interface

	config = newConfig
	if err := saveConfigToFile(); err != nil {
		http.Error(w, `{"error":"保存失败"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "配置已更新，需重启生效"})
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

func handleIndex(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile(indexHTMLPath)
	if err != nil {
		http.Error(w, "index.html not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(html)
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(config.WebUsername)) != 1 || 
		   subtle.ConstantTimeCompare([]byte(pass), []byte(config.WebPassword)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
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
	mux.HandleFunc("/api/config", basicAuth(handleAPIUpdateConfig))
	mux.HandleFunc("/api/autorotate", basicAuth(handleAPIAutoRotate))
	mux.HandleFunc("/api/autoclean", basicAuth(handleAPIAutoClean))

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

func main() {
	mrand.Seed(time.Now().UnixNano())
	
	log.Printf("IPv6 代理 v7.4 Final")

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
		log.Fatalf("无法解析前缀: %v", err)
	}
	iface, err = netlink.LinkByName(config.Interface)
	if err != nil {
		log.Fatalf("无法找到网卡: %v", err)
	}

	log.Printf("")
	log.Printf("配置: 代理:%s Web:%s", config.Port, config.WebPort)
	log.Printf("网络: %s::/64 @ %s", config.IPv6Prefix, config.Interface)
	log.Printf("IP池: %d → %d", config.InitialPool, config.TargetPool)
	if config.AutoRotate {
		log.Printf("轮换: 每 %d 小时", config.AutoRotateHours)
	}
	log.Printf("")

	if err := initIPv6Pool(); err != nil {
		log.Fatalf("初始化失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if config.TargetPool > config.InitialPool {
		atomic.StoreInt32(&backgroundRunning, 1) 
	}
	
	discardQueue = make(chan net.IP, 5000)

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

	webServer := startWebServer(ctx)

	listener, err := net.Listen("tcp", ":"+config.Port)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}

	log.Printf("✅ 服务就绪")

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "closed network connection") {
					break
				}
				continue
			}
			go handleConnection(conn)
		}
	}()

	<-shutdownChan
	log.Printf("\n关闭中...")
	cancel()
	webServer.Shutdown(context.Background())
	listener.Close()
	cleanupIPs()
	log.Printf("✅ 已关闭")
}
GOEOF

print_success "源代码完成"
echo ""

# --- 步骤 4: 创建前端 ---
echo "--- 步骤 4: 创建前端 ---"
cat << 'HTMLEOF' > index.html
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPv6 代理管理面板</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-card: #1a2332;
    --primary: #3b82f6;
    --primary-light: #60a5fa;
    --secondary: #06b6d4;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --border: #2d3748;
}

* {margin:0;padding:0;box-sizing:border-box}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
    background: linear-gradient(135deg, #0f172a 0%, #1a202c 100%);
    min-height: 100vh;
    color: var(--text-primary);
}

.container {
    max-width: 1600px;
    margin: 0 auto;
    padding: 20px;
}

.header {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 25px 30px;
    margin-bottom: 25px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border);
}

.header h1 {
    font-size: 26px;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 12px;
}

.header h1::before {
    content: '🚀';
    font-size: 28px;
}

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 25px;
}

.card {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border);
    transition: all 0.3s ease;
    position: relative;
}

.card:hover {
    transform: translateY(-3px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    border-color: var(--primary);
}

.card-title {
    font-size: 12px;
    color: var(--text-secondary);
    font-weight: 400;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 12px;
}

.card-value {
    font-size: 32px;
    font-weight: bold;
    color: var(--primary-light);
    line-height: 1;
}

.card-value-small {
    font-size: 22px;
    font-weight: bold;
}

.card-value-small .success {color: var(--success)}
.card-value-small .fail {color: var(--danger)}

.card-sub {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 8px;
}

.progress-bar {
    width: 100%;
    height: 6px;
    background: var(--bg-secondary);
    border-radius: 3px;
    overflow: hidden;
    margin-top: 12px;
}

.progress-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--primary), var(--primary-light));
    transition: width 0.5s ease;
}

.section {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 25px;
    margin-bottom: 25px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border);
}

.section-title {
    font-size: 18px;
    font-weight: 500;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 1px solid var(--border);
}

.log-container {
    max-height: 400px;
    overflow-y: auto;
    overflow-x: auto;
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 10px;
}

/* 滚动条样式 */
.log-container::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

.log-container::-webkit-scrollbar-track {
    background: var(--bg-secondary);
    border-radius: 4px;
}

.log-container::-webkit-scrollbar-thumb {
    background: var(--border);
    border-radius: 4px;
}

.log-container::-webkit-scrollbar-thumb:hover {
    background: var(--text-muted);
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 600px;
}

th {
    background: var(--bg-primary);
    padding: 12px 15px;
    text-align: left;
    font-weight: 500;
    color: var(--text-secondary);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 10;
}

td {
    padding: 10px 15px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
    color: var(--text-primary);
    white-space: nowrap;
}

tr:hover {
    background: rgba(59, 130, 246, 0.05);
}

.status-success {color: var(--success); font-weight: 500;}
.status-fail {color: var(--danger); font-weight: 500;}
.status-timeout {color: var(--warning); font-weight: 500;}

.input-group {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 15px;
}

input[type=number], input[type=text], input[type=password], select {
    padding: 10px 15px;
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 14px;
    transition: all 0.3s ease;
    background: var(--bg-secondary);
    color: var(--text-primary);
    min-width: 120px;
}

input[type=number]:focus, input[type=text]:focus, input[type=password]:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
}

input[type=number]::placeholder, input[type=text]::placeholder, input[type=password]::placeholder {
    color: var(--text-muted);
}

button {
    background: var(--primary);
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.3s ease;
    font-size: 14px;
    font-weight: 500;
}

button:hover {
    background: var(--primary-light);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
}

button.warning {
    background: var(--warning);
}

button.warning:hover {
    background: #d97706;
    box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
}

.badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.badge-success {
    background: rgba(16, 185, 129, 0.2);
    color: var(--success);
}

.badge-info {
    background: rgba(59, 130, 246, 0.2);
    color: var(--primary-light);
}

.chart-container {
    height: 250px;
    margin-top: 15px;
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 15px;
}

canvas {
    max-height: 220px;
}

/* 提示框样式 */
/* 标签样式 */
label {
    color: var(--text-secondary);
}

input[type=checkbox] {
    width: 18px;
    height: 18px;
    cursor: pointer;
}

/* 紧凑配置卡片样式 */
.config-card {
    min-height: 140px;
    display: flex;
    flex-direction: column;
}

.compact-form {
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex: 1;
}

.compact-input {
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 13px;
    background: var(--bg-secondary);
    color: var(--text-primary);
    width: 100%;
}

.compact-input:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
}

.compact-btn {
    padding: 6px 12px;
    font-size: 13px;
    border-radius: 6px;
    background: var(--primary);
    color: white;
    border: none;
    cursor: pointer;
    transition: all 0.3s ease;
    width: 100%;
}

.compact-btn:hover {
    background: var(--primary-light);
}

.compact-btn.warning {
    background: var(--warning);
}

.compact-btn.warning:hover {
    background: #d97706;
}

.checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    color: var(--text-primary);
}

.checkbox-label input {
    width: 16px;
    height: 16px;
}

.input-row {
    display: flex;
    align-items: center;
    gap: 5px;
}

.mini-label {
    font-size: 12px;
    color: var(--text-secondary);
    white-space: nowrap;
}

.unit {
    font-size: 12px;
    color: var(--text-muted);
}

.status-text {
    font-size: 11px;
    margin-top: 4px;
    height: 16px;
}

.info-text {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
}

@media (max-width: 768px) {
    .container {padding: 15px;}
    .grid {grid-template-columns: 1fr;}
    .header h1 {font-size: 20px;}
    .config-card {min-height: auto; padding: 15px;}
    .compact-form {gap: 10px;}
}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🚀 IPv6 代理管理面板 v7.4 Final</h1>
    </div>
    
    <!-- 数据统计卡片 -->
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
            <div class="card-title">连接统计</div>
            <div class="card-value-small">
                <span class="success" id="success">-</span> / <span class="fail" id="failed">-</span>
            </div>
            <div class="card-sub">超时: <span id="timeout">-</span></div>
        </div>
        
        <div class="card">
            <div class="card-title">进程 CPU</div>
            <div class="card-value" id="process-cpu">- %</div>
            <div class="card-sub">ipv6-proxy</div>
        </div>
        
        <div class="card">
            <div class="card-title">系统 CPU</div>
            <div class="card-value" id="system-cpu">- %</div>
            <div class="card-sub">服务器</div>
        </div>
        
        <div class="card">
            <div class="card-title">平均耗时</div>
            <div class="card-value" id="avg-duration">- ms</div>
        </div>
        
        <div class="card">
            <div class="card-title">IPv6 池</div>
            <div class="card-value" id="pool-size">-</div>
            <div class="card-sub">目标: <span id="pool-target">-</span></div>
            <div class="progress-bar">
                <div class="progress-fill" id="pool-progress"></div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-title">运行时间</div>
            <div class="card-value" style="font-size:20px" id="uptime">-</div>
        </div>
    </div>

    <!-- 功能控制卡片 -->
    <div class="grid">
        <!-- 在线配置卡片 -->
        <div class="card config-card">
            <div class="card-title">⚙️ 在线配置</div>
            <div class="compact-form">
                <input type="text" id="cfg-port" placeholder="代理端口" class="compact-input">
                <input type="text" id="cfg-web-port" placeholder="Web端口" class="compact-input">
                <input type="text" id="cfg-username" placeholder="用户名" class="compact-input">
                <input type="password" id="cfg-password" placeholder="密码" class="compact-input">
                <button onclick="saveConfig()" class="compact-btn">💾 保存配置</button>
                <div id="config-status" class="status-text"></div>
            </div>
        </div>

        <!-- 自动轮换卡片 -->
        <div class="card config-card">
            <div class="card-title">🔄 自动轮换</div>
            <div class="compact-form">
                <label class="checkbox-label">
                    <input type="checkbox" id="auto-rotate-enabled">
                    <span>启用</span>
                </label>
                <div class="input-row">
                    <label class="mini-label">间隔:</label>
                    <input type="number" id="auto-rotate-hours" value="6" min="1" max="168" class="compact-input">
                    <span class="unit">小时</span>
                </div>
                <button onclick="saveAutoRotate()" class="compact-btn">保存</button>
                <div id="auto-rotate-status" class="status-text"></div>
                <div id="next-rotate-info" class="info-text"></div>
            </div>
        </div>

        <!-- 自动清理卡片 -->
        <div class="card config-card">
            <div class="card-title">🧹 自动清理</div>
            <div class="compact-form">
                <label class="checkbox-label">
                    <input type="checkbox" id="auto-clean-enabled">
                    <span>启用失效IPv6自动删除补入</span>
                </label>
                <button onclick="saveAutoClean()" class="compact-btn">保存</button>
                <div id="auto-clean-status" class="status-text"></div>
                <div class="info-text">连接失败的IPv6将自动清理</div>
            </div>
        </div>

        <!-- IP池管理卡片 -->
        <div class="card config-card">
            <div class="card-title">📊 IP 池管理</div>
            <div class="compact-form">
                <label class="mini-label">目标:</label>
                <input type="number" id="new-target" placeholder="100000" min="100" step="1000" class="compact-input">
                <button onclick="resizePool()" class="compact-btn">应用</button>
                <button onclick="rotateIPs()" class="compact-btn warning">🔄 立即轮换</button>
                <div id="pool-status" class="status-text"></div>
            </div>
        </div>
    </div>

    <!-- 可视化图表 -->
    <div class="section">
        <div class="section-title">
            📊 性能监控
            <span class="badge badge-info">实时</span>
        </div>
        <div class="chart-container">
            <canvas id="statsChart"></canvas>
        </div>
    </div>

    <!-- 活动连接 -->
    <div class="section">
        <div class="section-title">
            👥 实时连接
            <span class="badge badge-info" id="active-count">0</span>
        </div>
        <div class="log-container">
            <table>
                <thead>
                    <tr>
                        <th>客户端</th>
                        <th>目标</th>
                        <th>IPv6</th>
                        <th>时长</th>
                    </tr>
                </thead>
                <tbody id="active-table">
                    <tr><td colspan="4" style="text-align:center;color:#64748b">无连接</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- 搜索 -->
    <div class="section">
        <div class="section-title">🔍 日志搜索</div>
        <div class="input-group">
            <input type="text" id="search-query" placeholder="搜索 IP、域名..." style="flex:1">
            <button onclick="searchLogs()">搜索</button>
            <button onclick="clearSearch()">清除</button>
            <span id="search-results-count"></span>
        </div>
        <div class="log-container" id="search-results-container" style="display:none">
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
                <tbody id="search-results-table"></tbody>
            </table>
        </div>
    </div>

    <!-- 最近连接 -->
    <div class="section">
        <div class="section-title">📝 最近连接</div>
        <div class="log-container">
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
                <tbody id="logs-table">
                    <tr><td colspan="6" style="text-align:center;color:#64748b">等待...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- 失败日志 -->
    <div class="section">
        <div class="section-title">❌ 失败日志</div>
        <div class="log-container">
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
                <tbody id="fail-logs-table">
                    <tr><td colspan="6" style="text-align:center;color:#64748b">无失败</td></tr>
                </tbody>
            </table>
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
            datasets: [
                {label: 'QPS', data: [], borderColor: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)', yAxisID: 'y', tension: 0.4, borderWidth: 2},
                {label: '成功率%', data: [], borderColor: '#10b981', backgroundColor: 'rgba(16, 185, 129, 0.1)', yAxisID: 'y1', tension: 0.4, borderWidth: 2},
                {label: 'CPU%', data: [], borderColor: '#f59e0b', backgroundColor: 'rgba(245, 158, 11, 0.1)', yAxisID: 'y1', tension: 0.4, borderWidth: 2}
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#94a3b8',
                        padding: 15,
                        font: {size: 12}
                    }
                },
                grid: {
                    color: '#2d3748'
                }
            },
            scales: {
                x: {
                    ticks: {color: '#64748b', font: {size: 11}},
                    grid: {color: '#2d3748', drawOnChartArea: true}
                },
                y: {
                    type: 'linear',
                    position: 'left',
                    ticks: {color: '#64748b', font: {size: 11}},
                    grid: {color: '#2d3748'}
                },
                y1: {
                    type: 'linear',
                    position: 'right',
                    ticks: {color: '#64748b', font: {size: 11}},
                    grid: {display: false}
                }
            }
        }
    });
}

async function updateStats() {
    try {
        const d = await fetch('/api/stats').then(r => r.json());
        document.getElementById('active').textContent = d.active;
        document.getElementById('total').textContent = d.total;
        document.getElementById('qps').textContent = d.qps.toFixed(2);
        document.getElementById('success').textContent = d.success;
        document.getElementById('failed').textContent = d.failed;
        document.getElementById('timeout').textContent = d.timeout;
        document.getElementById('process-cpu').textContent = d.process_cpu.toFixed(1) + ' %';
        document.getElementById('system-cpu').textContent = d.system_cpu.toFixed(1) + ' %';
        document.getElementById('avg-duration').textContent = d.avg_duration.toFixed(0) + ' ms';
        document.getElementById('pool-size').textContent = d.pool;
        document.getElementById('pool-target').textContent = d.target;
        document.getElementById('pool-progress').style.width = d.progress.toFixed(1) + '%';
        document.getElementById('uptime').textContent = d.uptime;
        document.getElementById('pool-status').innerHTML = d.bg_running ? '<span class="badge badge-info">运行中</span>' : '<span class="badge badge-success">就绪</span>';
        
        if (d.auto_rotate) {
            document.getElementById('auto-rotate-enabled').checked = true;
            document.getElementById('auto-rotate-hours').value = d.rotate_interval;
            document.getElementById('next-rotate-info').innerHTML = `⏰ 下次: <strong>${d.next_rotate}</strong>`;
        }
        
        if (d.auto_clean !== undefined) {
            document.getElementById('auto-clean-enabled').checked = d.auto_clean;
        }
    } catch (e) {}
}

async function updateChart() {
    try {
        const h = await fetch('/api/history').then(r => r.json());
        if (h.length === 0) return;
        statsChart.data.labels = h.map(x => x.timestamp);
        statsChart.data.datasets[0].data = h.map(x => x.qps);
        statsChart.data.datasets[1].data = h.map(x => x.success_rate);
        statsChart.data.datasets[2].data = h.map(x => x.process_cpu);
        statsChart.update('none');
    } catch (e) {}
}

function renderLogTable(tid, logs, msg) {
    const t = document.getElementById(tid);
    if (!logs || logs.length === 0) {
        t.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#64748b">${msg}</td></tr>`;
        return;
    }
    t.innerHTML = logs.map(l => {
        let c = l.status.includes('✅') ? 'status-success' : l.status.includes('⏱') ? 'status-timeout' : 'status-fail';
        return `<tr><td>${l.time}</td><td>${l.client_ip}</td><td>${l.target}</td><td>${l.ipv6}</td><td class="${c}">${l.status}</td><td>${l.duration}</td></tr>`;
    }).join('');
}

async function updateLogs() {
    try {
        const logs = await fetch('/api/logs').then(r => r.json());
        renderLogTable('logs-table', logs, '等待...');
    } catch (e) {}
}

async function updateFailLogs() {
    try {
        const logs = await fetch('/api/faillogs').then(r => r.json());
        renderLogTable('fail-logs-table', logs, '无失败');
    } catch (e) {}
}

async function updateActiveConns() {
    try {
        const conns = await fetch('/api/active').then(r => r.json());
        document.getElementById('active-count').textContent = conns.length;
        const t = document.getElementById('active-table');
        if (conns.length === 0) {
            t.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#64748b">无连接</td></tr>';
            return;
        }
        t.innerHTML = conns.map(c => `<tr><td>${c.client_ip}</td><td>${c.target}</td><td>${c.ipv6}</td><td>${c.duration}</td></tr>`).join('');
    } catch (e) {}
}

async function searchLogs() {
    const q = document.getElementById('search-query').value.trim();
    if (!q) {alert('请输入关键词'); return;}
    try {
        const r = await fetch(`/api/search?q=${encodeURIComponent(q)}`).then(r => r.json());
        document.getElementById('search-results-count').textContent = `找到 ${r.length} 条`;
        document.getElementById('search-results-container').style.display = 'block';
        renderLogTable('search-results-table', r, '未找到');
    } catch (e) {alert('搜索失败');}
}

function clearSearch() {
    document.getElementById('search-query').value = '';
    document.getElementById('search-results-count').textContent = '';
    document.getElementById('search-results-container').style.display = 'none';
}

async function saveConfig() {
    const cfg = {
        port: document.getElementById('cfg-port').value || '1080',
        web_port: document.getElementById('cfg-web-port').value || '8080',
        username: document.getElementById('cfg-username').value || 'proxy',
        password: document.getElementById('cfg-password').value || ''
    };
    try {
        const r = await fetch('/api/config', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(cfg)}).then(r => r.json());
        document.getElementById('config-status').innerHTML = '<span class="badge badge-success">✅ ' + r.message + '</span>';
        setTimeout(() => {document.getElementById('config-status').textContent = '';}, 5000);
    } catch (e) {alert('失败');}
}

async function saveAutoRotate() {
    const enabled = document.getElementById('auto-rotate-enabled').checked;
    const hours = parseInt(document.getElementById('auto-rotate-hours').value) || 6;
    try {
        const r = await fetch('/api/autorotate', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({enabled, interval: hours})}).then(r => r.json());
        document.getElementById('auto-rotate-status').innerHTML = '<span class="badge badge-success">✅ ' + r.message + '</span>';
        setTimeout(() => {document.getElementById('auto-rotate-status').textContent = ''; updateStats();}, 2000);
    } catch (e) {alert('失败');}
}

async function saveAutoClean() {
    const enabled = document.getElementById('auto-clean-enabled').checked;
    try {
        const r = await fetch('/api/autoclean', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({enabled})}).then(r => r.json());
        document.getElementById('auto-clean-status').innerHTML = '<span class="badge badge-success">✅ ' + r.message + '</span>';
        setTimeout(() => {document.getElementById('auto-clean-status').textContent = ''; updateStats();}, 2000);
    } catch (e) {alert('失败');}
}

async function resizePool() {
    const target = parseInt(document.getElementById('new-target').value);
    if (!target || target < 100) {alert('无效值'); return;}
    try {
        const r = await fetch('/api/pool/resize', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({target})}).then(r => r.json());
        alert(r.message);
        updateStats();
    } catch (e) {alert('失败');}
}

async function rotateIPs() {
    if (!confirm('确定轮换?')) return;
    try {
        const r = await fetch('/api/rotate', {method: 'POST'}).then(r => r.json());
        alert(r.message);
        updateStats();
    } catch (e) {alert('失败');}
}

document.getElementById('search-query').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') searchLogs();
});

initChart();
setInterval(updateStats, 3000);
setInterval(updateChart, 5000);
setInterval(updateLogs, 5000);
setInterval(updateFailLogs, 5000);
setInterval(updateActiveConns, 3000);
updateStats();
updateChart();
updateLogs();
updateFailLogs();
updateActiveConns();
</script>
</body>
</html>
HTMLEOF

print_success "前端完成"
echo ""

# --- 步骤 5: 编译 ---
echo "--- 步骤 5: 编译 ---"

# 检测是否在中国，配置GOPROXY
if ping -c 1 -W 1 goproxy.cn >/dev/null 2>&1; then
    export GOPROXY=https://goproxy.cn,direct
    echo "使用中国代理: goproxy.cn"
fi

/usr/local/go/bin/go mod init ipv6-proxy >/dev/null 2>&1
echo "下载依赖..."
/usr/local/go/bin/go mod tidy >/dev/null 2>&1 || {
    print_warning "下载依赖失败，重试..."
    handle_apt_locks
    /usr/local/go/bin/go mod tidy
}

echo "编译中..."
CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags "-s -w" -o ipv6-proxy . || {
    print_error "编译失败"
    exit 1
}
print_success "编译完成"
echo ""

# --- 步骤 6: 安装 ---
echo "--- 步骤 6: 安装 ---"
mkdir -p "$INSTALL_DIR"
mv ipv6-proxy "$INSTALL_DIR/"
mv index.html "$INSTALL_DIR/"
cd /
rm -rf "$BUILD_DIR"
print_success "安装完成"
echo ""

# --- 步骤 7: 创建服务 ---
echo "--- 步骤 7: 创建服务 ---"
cat << SERVICEEOF > /etc/systemd/system/ipv6-proxy.service
[Unit]
Description=IPv6 Proxy v7.4 Final
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
print_success "服务创建完成"
echo ""

# --- 配置 ---
echo "============================================="
echo "【首次配置】"
echo "============================================="
echo ""

# 运行配置
cd "$INSTALL_DIR"
./ipv6-proxy || true

echo ""
print_success "配置完成"
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
    ufw allow ${PROXY_PORT}/tcp comment "IPv6 Proxy" >/dev/null 2>&1 || true
    ufw allow ${WEB_PORT}/tcp comment "IPv6 Web Panel" >/dev/null 2>&1 || true
    
    print_success "防火墙已配置"
    echo "   代理: ${PROXY_PORT}/tcp"
    echo "   Web: ${WEB_PORT}/tcp"
else
    PROXY_PORT="1080"
    WEB_PORT="8080"
    print_warning "未检测到 ufw"
    echo "   手动配置: ufw allow ${PROXY_PORT}/tcp"
    echo "   手动配置: ufw allow ${WEB_PORT}/tcp"
fi
echo ""

# --- 启动 ---
echo "【启动服务】"
systemctl enable ipv6-proxy >/dev/null 2>&1
systemctl start ipv6-proxy

# 检查服务状态
sleep 2
if systemctl is-active --quiet ipv6-proxy; then
    print_success "服务启动成功"
else
    print_warning "服务启动可能失败，请检查："
    echo "   systemctl status ipv6-proxy"
fi

echo ""
echo "================================================"
echo "🎉 IPv6 代理 v7.4 Final 安装成功！"
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
echo "管理命令:"
echo "  systemctl status ipv6-proxy     # 查看状态"
echo "  systemctl restart ipv6-proxy    # 重启服务"
echo "  systemctl stop ipv6-proxy       # 停止服务"
echo "  journalctl -u ipv6-proxy -f     # 查看日志"
echo ""
echo "配置文件: $INSTALL_DIR/config.json"
echo ""
echo "🎊 享受你的 IPv6 代理服务！"
echo "================================================"
