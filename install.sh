#!/bin/bash
#
# IPv6 代理 v7.5  修复V6地址自动删除BUG
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
	Port              string       `json:"port"`
	WebPort           string       `json:"web_port"`
	WebUsername       string       `json:"web_username"`
	WebPassword       string       `json:"web_password"`
	Username          string       `json:"username"`
	Password          string       `json:"password"`
	IPv6Prefix        string       `json:"ipv6_prefix"`
	NextHopAddr       string       `json:"nexthop_addr"`  // BuyVM 路由子网的下一跳地址
	Interface         string       `json:"interface"`
	InitialPool       int          `json:"initial_pool"`
	TargetPool        int          `json:"target_pool"`
	AutoRotate        bool         `json:"auto_rotate"`
	AutoRotateHours   int          `json:"auto_rotate_hours"`
	AutoClean         bool         `json:"auto_clean"`
	Ports             []PortConfig `json:"ports"` // 多端口配置
}

type Stats struct {
	TotalConns, ActiveConns, SuccessConns, FailedConns int64
	TimeoutConns         int64
	PoolSize             int64
	StartTime            time.Time
	TotalDuration        int64
	ProcessCPUPercent    int64
	SystemCPUPercent     int64
	// 新增：流量统计
	TotalBytesRecv       int64
	TotalBytesSent       int64
	CurrentRecvRate      int64 // bytes per second
	CurrentSendRate      int64 // bytes per second
	LastTrafficUpdate    time.Time
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

// 新增：端口配置管理
type PortConfig struct {
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
	Created  string `json:"created"`
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
	prefixMap := make(map[string]string) // value: 完整的CIDR格式
	for _, addr := range addrs {
		if addr.IPNet != nil && addr.IPNet.IP.IsGlobalUnicast() {
			ones, bits := addr.IPNet.Mask.Size()
			if bits == 128 {
				// 支持 /48 和 /64
				if ones == 48 {
					ip48 := addr.IPNet.IP.Mask(net.CIDRMask(48, 128))
					prefixStr := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x",
						ip48[0], ip48[1], ip48[2], ip48[3], ip48[4], ip48[5])
					cidr := fmt.Sprintf("%s::/48", prefixStr)
					prefixMap[cidr] = cidr
				} else if ones == 64 {
					ip64 := addr.IPNet.IP.Mask(net.CIDRMask(64, 128))
					prefixStr := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x",
						ip64[0], ip64[1], ip64[2], ip64[3], ip64[4], ip64[5], ip64[6], ip64[7])
					cidr := fmt.Sprintf("%s::/64", prefixStr)
					prefixMap[cidr] = cidr
				} else if ones < 64 {
					// 对于 /56 等其他前缀，使用实际掩码
					ipPrefix := addr.IPNet.IP.Mask(net.CIDRMask(ones, 128))
					parts := make([]string, ones/16)
					for i := 0; i < ones/16; i++ {
						parts[i] = fmt.Sprintf("%02x%02x", ipPrefix[i*2], ipPrefix[i*2+1])
					}
					cidr := fmt.Sprintf("%s::/%d", strings.Join(parts, ":"), ones)
					prefixMap[cidr] = cidr
				}
			}
		}
	}
	if len(prefixMap) == 0 {
		log.Println("未检测到 IPv6 前缀")
		log.Println("请输入完整的 IPv6 前缀 (例如: 2605:6400:408c::/48 或 2605:6400:20:48::/64):")
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		return strings.TrimSpace(text), nil
	}
	
	// 排序：/48 排在前面
	var validPrefixes []string
	for cidr := range prefixMap {
		validPrefixes = append(validPrefixes, cidr)
	}
	sort.Slice(validPrefixes, func(i, j int) bool {
		// /48 优先
		if strings.Contains(validPrefixes[i], "/48") {
			return true
		}
		if strings.Contains(validPrefixes[j], "/48") {
			return false
		}
		return validPrefixes[i] < validPrefixes[j]
	})
	
	log.Println("检测到的 IPv6 前缀:")
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
	config.Password = readUserPassword("代理密码", "proxy")

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

	// 如果是 /48 或更大的路由子网，询问下一跳地址
	if strings.Contains(config.IPv6Prefix, "/48") || strings.Contains(config.IPv6Prefix, "/56") {
		log.Println("\n--- 路由子网配置 ---")
		log.Println("检测到路由子网，需要配置下一跳地址（NextHop Address）")
		log.Println("这通常是一个在 /64 子网中的地址，用于路由流量")
		config.NextHopAddr = readUserString("下一跳地址", "")
		
		if config.NextHopAddr == "" {
			log.Println("⚠️  警告：未配置下一跳地址")
			log.Println("   对于 BuyVM 等路由子网，需要先配置一个 /64 地址作为下一跳")
			log.Println("   否则代理可能无法正常工作")
		}
	}

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
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		},
		Flags: syscall.IFA_F_NODAD, // 禁用 DAD，立即可用
	}
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

func checkAuthForPort(proxyPort, user, pass string) bool {
	expectedUser := config.Username
	expectedPass := config.Password
	if proxyPort != "" && proxyPort != config.Port {
		found := false
		for _, p := range config.Ports {
			if p.Port == proxyPort && p.Enabled {
				expectedUser = p.Username
				expectedPass = p.Password
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return subtle.ConstantTimeCompare([]byte(user), []byte(expectedUser)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(expectedPass)) == 1
}

func transfer(dst net.Conn, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	deadline := time.Now().Add(120 * time.Second)
	src.SetReadDeadline(deadline)
	dst.SetWriteDeadline(deadline)
	buf := make([]byte, 64*1024)
	
	// 自定义复制以统计流量
	var totalBytes int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			totalBytes += int64(nr)
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			if ew != nil {
				break
			}
			if nr != nw {
				break
			}
		}
		if er != nil {
			break
		}
	}
	
	// 统计流量 - 根据src和dst的类型判断方向
	// 简化处理：统计所有传输的字节
	atomic.AddInt64(&stats.TotalBytesSent, totalBytes)
}

func handleSOCKS5(conn net.Conn, firstByte byte, proxyPort string) {
	defer conn.Close()
	defer atomic.AddInt64(&stats.ActiveConns, -1)
	buf := make([]byte, 512)
	buf[0] = firstByte
	if _, err := io.ReadFull(conn, buf[1:2]); err != nil {
		return
	}
	if buf[0] != 5 {
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return
	}
	hasUserPass := false
	for i := 0; i < nmethods; i++ {
		if buf[i] == 2 {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		conn.Write([]byte{5, 0xff})
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	conn.Write([]byte{5, 2})
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 1 {
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	ulen := int(buf[1])
	if ulen == 0 || ulen > 255 {
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	if _, err := io.ReadFull(conn, buf[:ulen]); err != nil {
		return
	}
	username := string(buf[:ulen])
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return
	}
	plen := int(buf[0])
	if plen == 0 || plen > 255 {
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	if _, err := io.ReadFull(conn, buf[:plen]); err != nil {
		return
	}
	password := string(buf[:plen])
	if !checkAuthForPort(proxyPort, username, password) {
		conn.Write([]byte{1, 1})
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	conn.Write([]byte{1, 0})
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 5 || buf[1] != 1 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&stats.FailedConns, 1)
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
		host = fm
