#!/bin/bash
#
# IPv6 代理 v7.4 Final (完全修复版) 一键安装脚本
#
# 修复：
# ✅ 编译错误修复
# ✅ 自动配置防火墙
# ✅ 双CPU监控
# ✅ 5个新功能完整实现
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
echo "=== IPv6 代理 v7.4 Final 安装中 ==="
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

func getInterface() error {
	log.Println("获取网卡信息...")
	l, err := selectInterface()
	if err != nil {
		return err
	}
	iface = l
	config.Interface = iface.Attrs().Name
	log.Printf("✅ 选择网卡: %s", config.Interface)
	
	for i := 0; i < 3; i++ {
		if err := checkIPv6(); err == nil {
			return nil
		}
		log.Printf("检查 IPv6 (%d/3)...", i+1)
		time.Sleep(2 * time.Second)
	}
	return errors.New("无法验证 IPv6 地址，请手动输入")
}

func checkIPv6() error {
	addrs, err := netlink.AddrList(iface, netlink.FAMILY_V6)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		ip := addr.IP
		if ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			config.IPv6Prefix = addr.IPNet.String()
			log.Printf("✅ 自动检测 IPv6 前缀: %s", config.IPv6Prefix)
			prefixIP, prefixNet, _ = net.ParseCIDR(config.IPv6Prefix)
			return nil
		}
	}
	return errors.New("未检测到有效的公网 IPv6 地址")
}

func setupConfig() error {
	log.Println()
	log.Println("【配置向导】")
	log.Println("====================")
	
	config.Port = readUserString("代理端口", "1080")
	config.Username = readUserString("代理用户名", "proxy")
	config.Password = readUserPassword("代理密码", "proxy123")
	
	log.Println()
	config.WebPort = readUserString("Web 端口", "8080")
	config.WebUsername = readUserString("Web 用户名", "admin")
	config.WebPassword = readUserPassword("Web 密码", "admin123")
	
	log.Println()
	if err := getInterface(); err != nil {
		config.IPv6Prefix = readUserString("IPv6 前缀 (如 2a0e:aa07:e038::/64)", "")
		if config.IPv6Prefix == "" {
			return errors.New("IPv6 前缀不能为空")
		}
		var err error
		prefixIP, prefixNet, err = net.ParseCIDR(config.IPv6Prefix)
		if err != nil {
			return fmt.Errorf("无效的 IPv6 前缀: %v", err)
		}
	}
	
	log.Println()
	config.InitialPool = readUserInt("初始池大小", 500)
	config.TargetPool = readUserInt("目标池大小", 1000)
	config.AutoRotate = readUserInt("自动轮换 (1=开启, 0=关闭)", 1) == 1
	if config.AutoRotate {
		config.AutoRotateHours = readUserInt("轮换间隔(小时)", 6)
		log.Printf("✅ 自动轮换: 每 %d 小时", config.AutoRotateHours)
	}
	config.AutoClean = readUserInt("自动清理失效IP (1=开启, 0=关闭)", 1) == 1
	if config.AutoClean {
		log.Println("✅ 自动清理: 已启用")
	}
	
	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(configFilePath, configData, 0644); err != nil {
		return err
	}
	log.Println()
	log.Printf("✅ 配置已保存: %s", configFilePath)
	return nil
}

func loadConfig() error {
	configData, err := os.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(configData, &config); err != nil {
		return err
	}
	prefixIP, prefixNet, err = net.ParseCIDR(config.IPv6Prefix)
	if err != nil {
		return fmt.Errorf("配置文件中的 IPv6 前缀无效: %v", err)
	}
	l, err := netlink.LinkByName(config.Interface)
	if err != nil {
		return fmt.Errorf("找不到网卡 %s: %v", config.Interface, err)
	}
	iface = l
	log.Printf("✅ 已加载配置: %s", configFilePath)
	return nil
}

func addIPToInterface(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("无效的 IP: %s", ipStr)
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		},
		Label: "",
	}
	if err := netlink.AddrAdd(iface, addr); err != nil && !strings.Contains(err.Error(), "exists") {
		return err
	}
	return nil
}

func removeIPFromInterface(ipStr string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("无效的 IP: %s", ipStr)
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		},
	}
	if err := netlink.AddrDel(iface, addr); err != nil && !strings.Contains(err.Error(), "cannot assign") {
		return err
	}
	return nil
}

func generateRandomIPv6() net.IP {
	ip := make(net.IP, len(prefixIP))
	copy(ip, prefixIP)
	rngLock.Lock()
	for i := 8; i < 16; i++ {
		ip[i] = byte(rng.Intn(256))
	}
	rngLock.Unlock()
	return ip
}

func isUniqueIP(ip net.IP) bool {
	poolLock.RLock()
	defer poolLock.RUnlock()
	_, exists := ipv6PoolIndex[ip.String()]
	return !exists
}

func generateUniqueIPv6() net.IP {
	for {
		ip := generateRandomIPv6()
		if isUniqueIP(ip) {
			return ip
		}
	}
}

func initPool() {
	poolLock.Lock()
	defer poolLock.Unlock()
	
	ipv6Pool = make([]net.IP, 0)
	ipv6PoolIndex = make(map[string]int)
	
	poolSize := config.InitialPool
	if poolSize < 100 {
		poolSize = 100
	}
	
	log.Printf("初始化 IP 池 (大小: %d)...", poolSize)
	addedCount := 0
	for addedCount < poolSize {
		ip := generateUniqueIPv6()
		if err := addIPToInterface(ip.String()); err == nil {
			ipv6Pool = append(ipv6Pool, ip)
			ipv6PoolIndex[ip.String()] = len(ipv6Pool) - 1
			addedCount++
			if addedCount%100 == 0 {
				log.Printf("  已添加 %d/%d IP", addedCount, poolSize)
			}
		}
	}
	atomic.StoreInt64(&stats.PoolSize, int64(len(ipv6Pool)))
	log.Printf("✅ IP 池初始化完成 (有效: %d)", len(ipv6Pool))
}

func backgroundAddIP() {
	for atomic.LoadInt32(&backgroundRunning) == 1 {
		targetPool := config.TargetPool
		if targetPool < 100 {
			targetPool = 100
		}
		
		poolLock.RLock()
		currentSize := len(ipv6Pool)
		poolLock.RUnlock()
		
		if currentSize >= targetPool {
			time.Sleep(5 * time.Second)
			continue
		}
		
		ip := generateUniqueIPv6()
		if err := addIPToInterface(ip.String()); err == nil {
			poolLock.Lock()
			ipv6Pool = append(ipv6Pool, ip)
			ipv6PoolIndex[ip.String()] = len(ipv6Pool) - 1
			poolLock.Unlock()
			
			atomic.AddInt64(&backgroundAdded, 1)
			atomic.StoreInt64(&stats.PoolSize, int64(currentSize+1))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func backgroundCleanup() {
	for {
		time.Sleep(10 * time.Second)
		cleanupStaleIPs()
	}
}

func cleanupStaleIPs() {
	select {
	case staleIP := <-discardQueue:
		ipStr := staleIP.String()
		poolLock.Lock()
		if idx, exists := ipv6PoolIndex[ipStr]; exists {
			removeIPFromInterface(ipStr)
			ipv6Pool = append(ipv6Pool[:idx], ipv6Pool[idx+1:]...)
			delete(ipv6PoolIndex, ipStr)
			for i := idx; i < len(ipv6Pool); i++ {
				ipv6PoolIndex[ipv6Pool[i].String()] = i
			}
		}
		poolLock.Unlock()
		atomic.StoreInt64(&stats.PoolSize, int64(len(ipv6Pool)))
	default:
	}
}

func startBackground() {
	if atomic.CompareAndSwapInt32(&backgroundRunning, 0, 1) {
		go backgroundAddIP()
		log.Println("✅ 后台 IP 生成已启动")
	}
}

func stopBackground() {
	atomic.StoreInt32(&backgroundRunning, 0)
	log.Println("⏸ 后台 IP 生成已停止")
}

func getRandomIP() net.IP {
	poolLock.RLock()
	defer poolLock.RUnlock()
	
	if len(ipv6Pool) == 0 {
		return nil
	}
	
	rngLock.Lock()
	idx := rng.Intn(len(ipv6Pool))
	rngLock.Unlock()
	
	return ipv6Pool[idx]
}

func rotateAllIPs() {
	log.Println("🔄 开始轮换所有 IP...")
	
	poolLock.Lock()
	oldPool := ipv6Pool
	ipv6Pool = make([]net.IP, 0)
	ipv6PoolIndex = make(map[string]int)
	poolLock.Unlock()
	
	for _, ip := range oldPool {
		removeIPFromInterface(ip.String())
	}
	log.Printf("已移除 %d 个旧 IP", len(oldPool))
	
	targetSize := len(oldPool)
	if targetSize < config.TargetPool {
		targetSize = config.TargetPool
	}
	
	addedCount := 0
	for addedCount < targetSize {
		ip := generateUniqueIPv6()
		if err := addIPToInterface(ip.String()); err == nil {
			poolLock.Lock()
			ipv6Pool = append(ipv6Pool, ip)
			ipv6PoolIndex[ip.String()] = len(ipv6Pool) - 1
			poolLock.Unlock()
			addedCount++
			if addedCount%100 == 0 {
				log.Printf("  已轮换 %d/%d IP", addedCount, targetSize)
			}
		}
	}
	
	atomic.StoreInt64(&stats.PoolSize, int64(len(ipv6Pool)))
	log.Printf("✅ 轮换完成 (新池: %d IP)", len(ipv6Pool))
}

func autoRotateWorker() {
	for {
		if atomic.LoadInt32(&autoRotateEnabled) == 1 {
			interval := time.Duration(atomic.LoadInt64(&autoRotateInterval)) * time.Hour
			nextRotateTimeLock.Lock()
			nextRotateTime = time.Now().Add(interval)
			nextRotateTimeLock.Unlock()
			
			time.Sleep(interval)
			
			if atomic.LoadInt32(&autoRotateEnabled) == 1 {
				log.Println("⏰ 自动轮换触发")
				rotateAllIPs()
			}
		} else {
			time.Sleep(10 * time.Second)
		}
	}
}

func autoCleanWorker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		if !config.AutoClean {
			continue
		}
		
		failLogsLock.RLock()
		failCount := make(map[string]int)
		for _, log := range failLogs {
			failCount[log.IPv6]++
		}
		failLogsLock.RUnlock()
		
		poolLock.Lock()
		for ipStr, count := range failCount {
			if count >= 5 {
				if idx, exists := ipv6PoolIndex[ipStr]; exists {
					log.Printf("🧹 清理失效 IP: %s (失败 %d 次)", ipStr, count)
					removeIPFromInterface(ipStr)
					ipv6Pool = append(ipv6Pool[:idx], ipv6Pool[idx+1:]...)
					delete(ipv6PoolIndex, ipStr)
					for i := idx; i < len(ipv6Pool); i++ {
						ipv6PoolIndex[ipv6Pool[i].String()] = i
					}
				}
			}
		}
		poolLock.Unlock()
		atomic.StoreInt64(&stats.PoolSize, int64(len(ipv6Pool)))
	}
}

func collectStats() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	lastTotal := int64(0)
	lastSuccess := int64(0)
	
	for range ticker.C {
		nowTotal := atomic.LoadInt64(&stats.TotalConns)
		nowSuccess := atomic.LoadInt64(&stats.SuccessConns)
		
		qps := float64(nowTotal-lastTotal) / 5.0
		successRate := 0.0
		if nowTotal-lastTotal > 0 {
			successRate = float64(nowSuccess-lastSuccess) / float64(nowTotal-lastTotal) * 100
		}
		
		processCPU := float64(atomic.LoadInt64(&stats.ProcessCPUPercent))
		systemCPU := float64(atomic.LoadInt64(&stats.SystemCPUPercent))
		activeConns := atomic.LoadInt64(&stats.ActiveConns)
		
		snapshot := &StatsSnapshot{
			Timestamp:   time.Now().Format("15:04:05"),
			QPS:         qps,
			SuccessRate: successRate,
			ProcessCPU:  processCPU,
			SystemCPU:   systemCPU,
			ActiveConns: activeConns,
		}
		
		statsHistoryLock.Lock()
		statsHistory = append(statsHistory, snapshot)
		if len(statsHistory) > maxHistory {
			statsHistory = statsHistory[1:]
		}
		statsHistoryLock.Unlock()
		
		lastTotal = nowTotal
		lastSuccess = nowSuccess
	}
}

func collectCPUMetrics() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	pid := int32(os.Getpid())
	p, err := process.NewProcess(pid)
	if err != nil {
		log.Printf("无法获取进程: %v", err)
		return
	}
	
	for range ticker.C {
		if cpuPercent, err := p.CPUPercent(); err == nil {
			atomic.StoreInt64(&stats.ProcessCPUPercent, int64(cpuPercent))
		}
		
		if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
			atomic.StoreInt64(&stats.SystemCPUPercent, int64(percents[0]))
		}
	}
}

func handleSOCKS5(clientConn net.Conn) {
	defer clientConn.Close()
	
	connID := fmt.Sprintf("%d", time.Now().UnixNano())
	clientAddr := clientConn.RemoteAddr().String()
	clientIP := strings.Split(clientAddr, ":")[0]
	
	activeConn := &ActiveConn{
		ID:        connID,
		ClientIP:  clientIP,
		StartTime: time.Now(),
	}
	
	activeConnectionsLock.Lock()
	activeConnections[connID] = activeConn
	activeConnectionsLock.Unlock()
	
	defer func() {
		activeConnectionsLock.Lock()
		delete(activeConnections, connID)
		activeConnectionsLock.Unlock()
		atomic.AddInt64(&stats.ActiveConns, -1)
	}()
	
	atomic.AddInt64(&stats.TotalConns, 1)
	atomic.AddInt64(&stats.ActiveConns, 1)
	
	startTime := time.Now()
	
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))
	
	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 {
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	
	if buf[0] != 0x05 {
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	
	numMethods := int(buf[1])
	if n < 2+numMethods {
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	
	hasAuth := false
	for i := 0; i < numMethods; i++ {
		if buf[2+i] == 0x02 {
			hasAuth = true
			break
		}
	}
	
	if config.Username != "" && config.Password != "" {
		if !hasAuth {
			clientConn.Write([]byte{0x05, 0xff})
			atomic.AddInt64(&stats.FailedConns, 1)
			return
		}
		clientConn.Write([]byte{0x05, 0x02})
		
		n, err = clientConn.Read(buf)
		if err != nil || n < 3 || buf[0] != 0x01 {
			atomic.AddInt64(&stats.FailedConns, 1)
			return
		}
		
		ulen := int(buf[1])
		if n < 3+ulen {
			atomic.AddInt64(&stats.FailedConns, 1)
			return
		}
		username := string(buf[2 : 2+ulen])
		
		plen := int(buf[2+ulen])
		if n < 3+ulen+plen {
			atomic.AddInt64(&stats.FailedConns, 1)
			return
		}
		password := string(buf[3+ulen : 3+ulen+plen])
		
		usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(config.Username)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(config.Password)) == 1
		
		if !usernameMatch || !passwordMatch {
			clientConn.Write([]byte{0x01, 0x01})
			atomic.AddInt64(&stats.FailedConns, 1)
			logConn(&ConnLog{
				Time:     time.Now().Format("15:04:05"),
				ClientIP: clientIP,
				Target:   "N/A",
				IPv6:     "N/A",
				Status:   "❌ 认证失败",
				Duration: fmt.Sprintf("%dms", time.Since(startTime).Milliseconds()),
			}, true)
			return
		}
		clientConn.Write([]byte{0x01, 0x00})
	} else {
		clientConn.Write([]byte{0x05, 0x00})
	}
	
	n, err = clientConn.Read(buf)
	if err != nil || n < 10 {
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	
	if buf[1] != 0x01 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	
	var targetHost string
	var targetPort uint16
	
	switch buf[3] {
	case 0x01:
		if n < 10 {
			atomic.AddInt64(&stats.FailedConns, 1)
			return
		}
		targetHost = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		targetPort = binary.BigEndian.Uint16(buf[8:10])
	case 0x03:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			atomic.AddInt64(&stats.FailedConns, 1)
			return
		}
		targetHost = string(buf[5 : 5+domainLen])
		targetPort = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])
	case 0x04:
		if n < 22 {
			atomic.AddInt64(&stats.FailedConns, 1)
			return
		}
		targetHost = net.IP(buf[4:20]).String()
		targetPort = binary.BigEndian.Uint16(buf[20:22])
	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	activeConn.Target = targetAddr
	
	selectedIP := getRandomIP()
	if selectedIP == nil {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&stats.FailedConns, 1)
		logConn(&ConnLog{
			Time:     time.Now().Format("15:04:05"),
			ClientIP: clientIP,
			Target:   targetAddr,
			IPv6:     "N/A",
			Status:   "❌ 无可用 IP",
			Duration: fmt.Sprintf("%dms", time.Since(startTime).Milliseconds()),
		}, true)
		return
	}
	
	activeConn.IPv6 = selectedIP.String()
	
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP: selectedIP,
		},
		Timeout: 10 * time.Second,
	}
	
	remoteConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&stats.FailedConns, 1)
		
		status := "❌ 连接失败"
		if strings.Contains(err.Error(), "timeout") {
			status = "⏱ 超时"
			atomic.AddInt64(&stats.TimeoutConns, 1)
		}
		
		logConn(&ConnLog{
			Time:     time.Now().Format("15:04:05"),
			ClientIP: clientIP,
			Target:   targetAddr,
			IPv6:     selectedIP.String(),
			Status:   status,
			Duration: fmt.Sprintf("%dms", time.Since(startTime).Milliseconds()),
		}, true)
		
		if config.AutoClean && strings.Contains(err.Error(), "timeout") {
			select {
			case discardQueue <- selectedIP:
			default:
			}
		}
		return
	}
	defer remoteConn.Close()
	
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	clientConn.SetDeadline(time.Time{})
	
	atomic.AddInt64(&stats.SuccessConns, 1)
	
	logConn(&ConnLog{
		Time:     time.Now().Format("15:04:05"),
		ClientIP: clientIP,
		Target:   targetAddr,
		IPv6:     selectedIP.String(),
		Status:   "✅ 成功",
		Duration: fmt.Sprintf("%dms", time.Since(startTime).Milliseconds()),
	}, false)
	
	var wg sync.WaitGroup
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				break
			}
			if _, err := remoteConn.Write(buf[:n]); err != nil {
				break
			}
		}
	}()
	
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := remoteConn.Read(buf)
			if err != nil {
				break
			}
			if _, err := clientConn.Write(buf[:n]); err != nil {
				break
			}
		}
	}()
	
	wg.Wait()
	
	duration := time.Since(startTime)
	atomic.AddInt64(&stats.TotalDuration, duration.Milliseconds())
}

func logConn(log *ConnLog, isFailed bool) {
	if isFailed {
		failLogsLock.Lock()
		failLogs = append([]*ConnLog{log}, failLogs...)
		if len(failLogs) > maxLogs {
			failLogs = failLogs[:maxLogs]
		}
		failLogsLock.Unlock()
	}
	
	connLogsLock.Lock()
	connLogs = append([]*ConnLog{log}, connLogs...)
	if len(connLogs) > maxLogs {
		connLogs = connLogs[:maxLogs]
	}
	connLogsLock.Unlock()
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != config.WebUsername || pass != config.WebPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="Admin Panel"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func handleWebStats(w http.ResponseWriter, r *http.Request) {
	total := atomic.LoadInt64(&stats.TotalConns)
	active := atomic.LoadInt64(&stats.ActiveConns)
	success := atomic.LoadInt64(&stats.SuccessConns)
	failed := atomic.LoadInt64(&stats.FailedConns)
	timeout := atomic.LoadInt64(&stats.TimeoutConns)
	poolSize := atomic.LoadInt64(&stats.PoolSize)
	totalDuration := atomic.LoadInt64(&stats.TotalDuration)
	processCPU := atomic.LoadInt64(&stats.ProcessCPUPercent)
	systemCPU := atomic.LoadInt64(&stats.SystemCPUPercent)
	
	uptime := time.Since(stats.StartTime)
	uptimeStr := fmt.Sprintf("%dd %dh %dm", int(uptime.Hours())/24, int(uptime.Hours())%24, int(uptime.Minutes())%60)
	
	successRate := float64(0)
	if total > 0 {
		successRate = float64(success) / float64(total) * 100
	}
	
	avgDuration := int64(0)
	if success > 0 {
		avgDuration = totalDuration / success
	}
	
	targetPool := config.TargetPool
	progress := float64(poolSize) / float64(targetPool) * 100
	if progress > 100 {
		progress = 100
	}
	
	nextRotateTimeLock.RLock()
	nextRotate := "未启用"
	if atomic.LoadInt32(&autoRotateEnabled) == 1 {
		nextRotate = nextRotateTime.Format("15:04:05")
	}
	nextRotateTimeLock.RUnlock()
	
	data := map[string]interface{}{
		"total":           total,
		"active":          active,
		"success":         success,
		"failed":          failed,
		"timeout":         timeout,
		"pool":            poolSize,
		"target":          targetPool,
		"progress":        progress,
		"success_rate":    successRate,
		"process_cpu":     processCPU,
		"system_cpu":      systemCPU,
		"avg_duration":    avgDuration,
		"uptime":          uptimeStr,
		"bg_running":      atomic.LoadInt32(&backgroundRunning) == 1,
		"bg_added":        atomic.LoadInt64(&backgroundAdded),
		"auto_rotate":     atomic.LoadInt32(&autoRotateEnabled) == 1,
		"rotate_interval": atomic.LoadInt64(&autoRotateInterval),
		"next_rotate":     nextRotate,
		"auto_clean":      config.AutoClean,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func handleWebHistory(w http.ResponseWriter, r *http.Request) {
	statsHistoryLock.RLock()
	history := make([]*StatsSnapshot, len(statsHistory))
	copy(history, statsHistory)
	statsHistoryLock.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func handleWebLogs(w http.ResponseWriter, r *http.Request) {
	connLogsLock.RLock()
	logs := make([]*ConnLog, len(connLogs))
	copy(logs, connLogs)
	connLogsLock.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func handleWebFailLogs(w http.ResponseWriter, r *http.Request) {
	failLogsLock.RLock()
	logs := make([]*ConnLog, len(failLogs))
	copy(logs, failLogs)
	failLogsLock.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func handleWebActive(w http.ResponseWriter, r *http.Request) {
	activeConnectionsLock.RLock()
	conns := make([]*ActiveConn, 0, len(activeConnections))
	for _, conn := range activeConnections {
		c := *conn
		c.Duration = fmt.Sprintf("%.1fs", time.Since(conn.StartTime).Seconds())
		conns = append(conns, &c)
	}
	activeConnectionsLock.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conns)
}

func handleWebSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		json.NewEncoder(w).Encode([]ConnLog{})
		return
	}
	
	connLogsLock.RLock()
	results := make([]*ConnLog, 0)
	for _, log := range connLogs {
		if strings.Contains(log.ClientIP, query) ||
		   strings.Contains(log.Target, query) ||
		   strings.Contains(log.IPv6, query) {
			results = append(results, log)
		}
	}
	connLogsLock.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleWebConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var newConfig struct {
		Port     string `json:"port"`
		WebPort  string `json:"web_port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	if newConfig.Port != "" {
		config.Port = newConfig.Port
	}
	if newConfig.WebPort != "" {
		config.WebPort = newConfig.WebPort
	}
	if newConfig.Username != "" {
		config.Username = newConfig.Username
	}
	if newConfig.Password != "" {
		config.Password = newConfig.Password
	}
	
	configData, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFilePath, configData, 0644)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "配置已保存，重启后生效",
	})
}

func handleWebRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	go rotateAllIPs()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "IP 轮换已开始",
	})
}

func handleWebPoolResize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Target int `json:"target"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	if req.Target < 100 {
		req.Target = 100
	}
	
	config.TargetPool = req.Target
	configData, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFilePath, configData, 0644)
	
	if atomic.LoadInt32(&backgroundRunning) == 0 {
		startBackground()
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("目标池大小已设为 %d", req.Target),
	})
}

func handleWebAutoRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Enabled  bool `json:"enabled"`
		Interval int  `json:"interval"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	config.AutoRotate = req.Enabled
	if req.Interval > 0 {
		config.AutoRotateHours = req.Interval
	}
	
	if req.Enabled {
		atomic.StoreInt32(&autoRotateEnabled, 1)
		atomic.StoreInt64(&autoRotateInterval, int64(config.AutoRotateHours))
	} else {
		atomic.StoreInt32(&autoRotateEnabled, 0)
	}
	
	configData, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFilePath, configData, 0644)
	
	status := "已关闭"
	if req.Enabled {
		status = fmt.Sprintf("已启用 (每 %d 小时)", config.AutoRotateHours)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("自动轮换 %s", status),
	})
}

func handleWebAutoClean(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Enabled bool `json:"enabled"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	config.AutoClean = req.Enabled
	
	configData, _ := json.MarshalIndent(config, "", "  ")
	os.WriteFile(configFilePath, configData, 0644)
	
	status := "已关闭"
	if req.Enabled {
		status = "已启用"
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("自动清理 %s", status),
	})
}

func handleWebIndex(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(indexHTMLPath)
	if err != nil {
		http.Error(w, "页面未找到", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func startWebServer() {
	http.HandleFunc("/", basicAuth(handleWebIndex))
	http.HandleFunc("/api/stats", basicAuth(handleWebStats))
	http.HandleFunc("/api/history", basicAuth(handleWebHistory))
	http.HandleFunc("/api/logs", basicAuth(handleWebLogs))
	http.HandleFunc("/api/faillogs", basicAuth(handleWebFailLogs))
	http.HandleFunc("/api/active", basicAuth(handleWebActive))
	http.HandleFunc("/api/search", basicAuth(handleWebSearch))
	http.HandleFunc("/api/config", basicAuth(handleWebConfig))
	http.HandleFunc("/api/rotate", basicAuth(handleWebRotate))
	http.HandleFunc("/api/pool/resize", basicAuth(handleWebPoolResize))
	http.HandleFunc("/api/autorotate", basicAuth(handleWebAutoRotate))
	http.HandleFunc("/api/autoclean", basicAuth(handleWebAutoClean))
	
	addr := fmt.Sprintf(":%s", config.WebPort)
	log.Printf("✅ Web 面板已启动: http://0.0.0.0%s", addr)
	log.Printf("   用户名: %s", config.WebUsername)
	log.Printf("   密码: %s", config.WebPassword)
	
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("Web 服务器错误: %v", err)
	}
}

func startProxyServer() {
	addr := fmt.Sprintf(":%s", config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()
	
	log.Printf("✅ SOCKS5 代理已启动: 0.0.0.0%s", addr)
	if config.Username != "" && config.Password != "" {
		log.Printf("   认证已启用 (用户: %s)", config.Username)
	} else {
		log.Println("   ⚠️  认证未启用")
	}
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleSOCKS5(conn)
	}
}

func printBanner() {
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║       IPv6 代理 v7.4 Final              ║")
	fmt.Println("║       高性能 SOCKS5 代理服务器          ║")
	fmt.Println("╚════════════════════════════════════════╝")
	fmt.Println()
}

func main() {
	printBanner()
	
	configFilePath = filepath.Join(filepath.Dir(os.Args[0]), "config.json")
	indexHTMLPath = filepath.Join(filepath.Dir(os.Args[0]), "index.html")
	
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		log.Println("配置文件不存在，启动配置向导...")
		if err := setupConfig(); err != nil {
			log.Fatalf("配置失败: %v", err)
		}
		log.Println()
		log.Println("✅ 配置完成！请重新运行程序启动服务。")
		os.Exit(0)
	}
	
	if err := loadConfig(); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	
	stats.StartTime = time.Now()
	discardQueue = make(chan net.IP, 100)
	
	initPool()
	
	poolLock.RLock()
	currentSize := len(ipv6Pool)
	poolLock.RUnlock()
	
	if currentSize < config.TargetPool {
		startBackground()
	}
	
	if config.AutoRotate {
		atomic.StoreInt32(&autoRotateEnabled, 1)
		atomic.StoreInt64(&autoRotateInterval, int64(config.AutoRotateHours))
		go autoRotateWorker()
		log.Printf("✅ 自动轮换已启用 (每 %d 小时)", config.AutoRotateHours)
	}
	
	if config.AutoClean {
		go autoCleanWorker()
		log.Println("✅ 自动清理已启用")
	}
	
	go backgroundCleanup()
	go collectStats()
	go collectCPUMetrics()
	
	go startWebServer()
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\n正在清理...")
		stopBackground()
		
		poolLock.RLock()
		for _, ip := range ipv6Pool {
			removeIPFromInterface(ip.String())
		}
		poolLock.RUnlock()
		
		log.Println("✅ 清理完成，退出")
		os.Exit(0)
	}()
	
	startProxyServer()
}
GOEOF

echo "✅ 源码创建完成"
echo ""

# --- 创建前端 ---
echo "--- 步骤 4: 创建前端 ---"
cat << 'HTMLEOF' > index.html
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPv6 代理管理面板</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {
    --primary: #4f46e5;
    --primary-dark: #4338ca;
    --secondary: #06b6d4;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --dark: #1e293b;
    --light: #f1f5f9;
    --border: #e2e8f0;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    color: #334155;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
}

.header {
    background: rgba(255, 255, 255, 0.98);
    border-radius: 16px;
    padding: 25px 30px;
    margin-bottom: 25px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
}

.header h1 {
    font-size: 28px;
    color: var(--dark);
    display: flex;
    align-items: center;
    gap: 12px;
}

.header h1::before {
    content: '🚀';
    font-size: 32px;
}

.dashboard {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 20px;
    margin-bottom: 25px;
}

.card {
    background: rgba(255, 255, 255, 0.98);
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
}

.card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--primary) 0%, var(--secondary) 100%);
}

.card-icon {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    margin-bottom: 15px;
}

.card-icon.blue { background: linear-gradient(135deg, #667eea, #764ba2); }
.card-icon.green { background: linear-gradient(135deg, #10b981, #059669); }
.card-icon.orange { background: linear-gradient(135deg, #f59e0b, #d97706); }
.card-icon.red { background: linear-gradient(135deg, #ef4444, #dc2626); }
.card-icon.purple { background: linear-gradient(135deg, #8b5cf6, #7c3aed); }
.card-icon.cyan { background: linear-gradient(135deg, #06b6d4, #0891b2); }

.stat-label {
    font-size: 13px;
    color: #64748b;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
}

.stat-value {
    font-size: 32px;
    font-weight: 700;
    color: var(--dark);
    line-height: 1;
}

.stat-unit {
    font-size: 14px;
    color: #94a3b8;
    margin-left: 4px;
}

.progress-bar {
    height: 8px;
    background: var(--light);
    border-radius: 4px;
    overflow: hidden;
    margin-top: 12px;
}

.progress-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--primary), var(--secondary));
    border-radius: 4px;
    transition: width 0.5s ease;
}

.chart-container {
    background: rgba(255, 255, 255, 0.98);
    border-radius: 12px;
    padding: 25px;
    margin-bottom: 25px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
}

.section {
    background: rgba(255, 255, 255, 0.98);
    border-radius: 12px;
    padding: 25px;
    margin-bottom: 25px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
}

.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 2px solid var(--border);
}

.section-title {
    font-size: 20px;
    font-weight: 600;
    color: var(--dark);
    display: flex;
    align-items: center;
    gap: 10px;
}

.section-title::before {
    font-size: 24px;
}

.controls {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

.btn {
    padding: 10px 20px;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.3s ease;
    display: inline-flex;
    align-items: center;
    gap: 8px;
}

.btn-primary {
    background: linear-gradient(135deg, var(--primary), var(--primary-dark));
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
}

.btn-success {
    background: linear-gradient(135deg, var(--success), #059669);
    color: white;
}

.btn-danger {
    background: linear-gradient(135deg, var(--danger), #dc2626);
    color: white;
}

.btn-secondary {
    background: var(--light);
    color: var(--dark);
    border: 1px solid var(--border);
}

.table-wrapper {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: white;
}

th {
    background: linear-gradient(135deg, #f8fafc, #f1f5f9);
    padding: 12px 15px;
    text-align: left;
    font-weight: 600;
    color: var(--dark);
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 2px solid var(--border);
}

td {
    padding: 12px 15px;
    border-bottom: 1px solid #f1f5f9;
    font-size: 14px;
    color: #475569;
}

tr:hover {
    background: #f8fafc;
}

tr:last-child td {
    border-bottom: none;
}

.form-group {
    margin-bottom: 20px;
}

.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
    color: var(--dark);
    font-size: 14px;
}

.form-control {
    width: 100%;
    padding: 10px 15px;
    border: 2px solid var(--border);
    border-radius: 8px;
    font-size: 14px;
    transition: all 0.3s ease;
    background: white;
}

.form-control:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
}

.form-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}

.checkbox-group {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 15px;
}

.checkbox-group input[type="checkbox"] {
    width: 20px;
    height: 20px;
    cursor: pointer;
}

.badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.badge-success {
    background: rgba(16, 185, 129, 0.1);
    color: var(--success);
}

.badge-danger {
    background: rgba(239, 68, 68, 0.1);
    color: var(--danger);
}

.badge-warning {
    background: rgba(245, 158, 11, 0.1);
    color: var(--warning);
}

.badge-info {
    background: rgba(6, 182, 212, 0.1);
    color: var(--secondary);
}

.search-box {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
}

.search-box input {
    flex: 1;
}

.tabs {
    display: flex;
    gap: 5px;
    margin-bottom: 20px;
    border-bottom: 2px solid var(--border);
}

.tab {
    padding: 12px 24px;
    background: transparent;
    border: none;
    color: #64748b;
    cursor: pointer;
    font-weight: 500;
    font-size: 14px;
    transition: all 0.3s ease;
    position: relative;
}

.tab.active {
    color: var(--primary);
}

.tab.active::after {
    content: '';
    position: absolute;
    bottom: -2px;
    left: 0;
    right: 0;
    height: 2px;
    background: var(--primary);
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
}

.status-success { color: var(--success); font-weight: 600; }
.status-fail { color: var(--danger); font-weight: 600; }
.status-timeout { color: var(--warning); font-weight: 600; }

.loading {
    display: inline-block;
    width: 20px;
    height: 20px;
    border: 3px solid rgba(0, 0, 0, 0.1);
    border-top-color: var(--primary);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

.empty-state {
    text-align: center;
    padding: 40px;
    color: #94a3b8;
}

.empty-state::before {
    content: '📭';
    font-size: 48px;
    display: block;
    margin-bottom: 15px;
    opacity: 0.5;
}

@media (max-width: 768px) {
    .container {
        padding: 15px;
    }
    
    .dashboard {
        grid-template-columns: 1fr;
    }
    
    .header h1 {
        font-size: 22px;
    }
    
    .controls {
        flex-direction: column;
    }
    
    .btn {
        width: 100%;
        justify-content: center;
    }
    
    .form-row {
        grid-template-columns: 1fr;
    }
}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>IPv6 代理管理面板</h1>
    </div>

    <!-- 数据统计卡片 -->
    <div class="dashboard">
        <div class="card">
            <div class="card-icon blue">📊</div>
            <div class="stat-label">总连接数</div>
            <div class="stat-value" id="total-conns">0</div>
        </div>
        
        <div class="card">
            <div class="card-icon green">✅</div>
            <div class="stat-label">成功连接</div>
            <div class="stat-value" id="success-conns">0</div>
        </div>
        
        <div class="card">
            <div class="card-icon red">❌</div>
            <div class="stat-label">失败连接</div>
            <div class="stat-value" id="failed-conns">0</div>
        </div>
        
        <div class="card">
            <div class="card-icon orange">⏱</div>
            <div class="stat-label">超时连接</div>
            <div class="stat-value" id="timeout-conns">0</div>
        </div>
    </div>

    <!-- 状态监控卡片 -->
    <div class="dashboard">
        <div class="card">
            <div class="card-icon purple">🔗</div>
            <div class="stat-label">活动连接</div>
            <div class="stat-value" id="active-conns">0</div>
        </div>
        
        <div class="card">
            <div class="card-icon cyan">📈</div>
            <div class="stat-label">成功率</div>
            <div class="stat-value">
                <span id="success-rate">0</span><span class="stat-unit">%</span>
            </div>
        </div>
        
        <div class="card">
            <div class="card-icon blue">💻</div>
            <div class="stat-label">进程 CPU / 系统 CPU</div>
            <div class="stat-value">
                <span id="process-cpu">0</span> / <span id="system-cpu">0</span><span class="stat-unit">%</span>
            </div>
        </div>
        
        <div class="card">
            <div class="card-icon green">⚡</div>
            <div class="stat-label">平均延迟</div>
            <div class="stat-value">
                <span id="avg-duration">0</span><span class="stat-unit">ms</span>
            </div>
        </div>
    </div>

    <!-- 功能控制区 -->
    <div class="dashboard">
        <div class="card">
            <div class="stat-label">🔧 基础配置</div>
            <div class="form-row">
                <input type="text" class="form-control" id="cfg-port" placeholder="代理端口">
                <input type="text" class="form-control" id="cfg-web-port" placeholder="Web端口">
            </div>
            <div class="form-row" style="margin-top: 10px;">
                <input type="text" class="form-control" id="cfg-username" placeholder="用户名">
                <input type="password" class="form-control" id="cfg-password" placeholder="密码">
            </div>
            <button class="btn btn-primary" style="margin-top: 15px; width: 100%;" onclick="saveConfig()">
                💾 保存配置
            </button>
            <div id="config-status" style="margin-top: 10px;"></div>
        </div>

        <div class="card">
            <div class="stat-label">🔄 自动轮换</div>
            <div class="checkbox-group">
                <input type="checkbox" id="auto-rotate-enabled">
                <label for="auto-rotate-enabled">启用自动轮换</label>
            </div>
            <div class="form-group">
                <label>轮换间隔 (小时)</label>
                <input type="number" class="form-control" id="auto-rotate-hours" value="6" min="1">
            </div>
            <button class="btn btn-success" style="width: 100%;" onclick="saveAutoRotate()">
                ⏰ 更新设置
            </button>
            <div id="next-rotate-info" style="margin-top: 10px;"></div>
            <div id="auto-rotate-status" style="margin-top: 5px;"></div>
        </div>

        <div class="card">
            <div class="stat-label">🧹 自动清理</div>
            <div class="checkbox-group">
                <input type="checkbox" id="auto-clean-enabled">
                <label for="auto-clean-enabled">启用失效IP自动清理</label>
            </div>
            <p style="font-size: 12px; color: #64748b; margin: 10px 0;">
                自动移除连续失败5次的IP地址
            </p>
            <button class="btn btn-success" style="width: 100%;" onclick="saveAutoClean()">
                🗑️ 更新设置
            </button>
            <div id="auto-clean-status" style="margin-top: 10px;"></div>
        </div>

        <div class="card">
            <div class="stat-label">🎯 池管理</div>
            <div style="margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span>当前: <strong id="pool-size">0</strong></span>
                    <span>目标: <strong id="pool-target">0</strong></span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="pool-progress"></div>
                </div>
                <div id="pool-status" style="margin-top: 8px; text-align: center;"></div>
            </div>
            <div class="form-group">
                <label>新目标大小</label>
                <input type="number" class="form-control" id="new-target" placeholder="1000" min="100">
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <button class="btn btn-primary" onclick="resizePool()">📏 调整</button>
                <button class="btn btn-danger" onclick="rotateIPs()">🔄 轮换</button>
            </div>
        </div>
    </div>

    <!-- 可视化图表 -->
    <div class="chart-container">
        <div class="section-title" style="margin-bottom: 20px;">
            <span>📊</span> 性能监控
        </div>
        <canvas id="stats-chart" height="80"></canvas>
    </div>

    <!-- 日志记录 -->
    <div class="section">
        <div class="section-header">
            <div class="section-title">
                <span>📝</span> 日志记录
            </div>
            <div class="controls">
                <span style="margin-right: 10px;">
                    <span>运行时间: </span>
                    <strong id="uptime">0d 0h 0m</strong>
                </span>
                <span>
                    <span>活动: </span>
                    <strong id="active-count">0</strong>
                </span>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="switchTab(event, 'logs-tab')">最近连接</button>
            <button class="tab" onclick="switchTab(event, 'fail-tab')">失败记录</button>
            <button class="tab" onclick="switchTab(event, 'active-tab')">活动连接</button>
            <button class="tab" onclick="switchTab(event, 'search-tab')">搜索</button>
        </div>

        <div id="logs-tab" class="tab-content active">
            <div class="table-wrapper">
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
        </div>

        <div id="fail-tab" class="tab-content">
            <div class="table-wrapper">
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
        </div>

        <div id="active-tab" class="tab-content">
            <div class="table-wrapper">
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

        <div id="search-tab" class="tab-content">
            <div class="search-box">
                <input type="text" class="form-control" id="search-query" placeholder="搜索 IP、目标或 IPv6...">
                <button class="btn btn-primary" onclick="searchLogs()">🔍 搜索</button>
                <button class="btn btn-secondary" onclick="clearSearch()">清空</button>
            </div>
            <div id="search-results-container" style="display:none;">
                <div style="margin-bottom: 10px;">
                    <span id="search-results-count"></span>
                </div>
                <div class="table-wrapper">
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
        </div>
    </div>
</div>

<script>
let statsChart;

function switchTab(event, tabName) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById(tabName).classList.add('active');
}

function initChart() {
    const ctx = document.getElementById('stats-chart').getContext('2d');
    statsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'QPS',
                    data: [],
                    borderColor: '#4f46e5',
                    backgroundColor: 'rgba(79, 70, 229, 0.1)',
                    tension: 0.3,
                    yAxisID: 'y'
                },
                {
                    label: '成功率 (%)',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.3,
                    yAxisID: 'y1'
                },
                {
                    label: 'CPU (%)',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.3,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                x: {
                    display: true,
                    grid: {
                        display: false
                    }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'QPS'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: '百分比 (%)'
                    },
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    });
}

async function updateStats() {
    try {
        const d = await fetch('/api/stats').then(r => r.json());
        document.getElementById('total-conns').textContent = d.total;
        document.getElementById('success-conns').textContent = d.success;
        document.getElementById('failed-conns').textContent = d.failed;
        document.getElementById('timeout-conns').textContent = d.timeout;
        document.getElementById('active-conns').textContent = d.active;
        document.getElementById('success-rate').textContent = d.success_rate.toFixed(1);
        document.getElementById('process-cpu').textContent = d.process_cpu.toFixed(1);
        document.getElementById('system-cpu').textContent = d.system_cpu.toFixed(1);
        document.getElementById('avg-duration').textContent = d.avg_duration.toFixed(0);
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
echo "🎉 v7.4 Final 安装成功！"
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
echo "  systemctl status ipv6-proxy"
echo "  journalctl -u ipv6-proxy -f"
echo "  systemctl restart ipv6-proxy"
echo ""
echo "🎊 享受 v7.4 Final！"
echo ""
