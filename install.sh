#!/bin/bash

#================================================================================
# IPv6 代理 (v6.2) 全自动安装脚本
#================================================================================

# --- 配置 ---
# 目标路径
PROJECT_PATH="/root/ip"
# Go 程序文件名
GO_BINARY="ipv6-proxy"
# Systemd 服务名称
SERVICE_NAME="ipv6-proxy.service"

# --- 颜色定义 ---
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m" # No Color

# --- 辅助函数 ---
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "此脚本必须以 root 身份运行。请使用 'sudo ./install.sh'"
    fi
}

# --- 步骤 1：安装依赖 ---
install_deps() {
    log_info "正在更新软件源 (apt update)..."
    if ! apt-get update -y; then
        log_error "apt update 失败。请检查您的网络和软件源。"
    fi
    
    log_info "正在安装 Go 语言环境 (golang-go) 和 curl..."
    if ! apt-get install -y golang-go curl; then
        log_error "依赖安装失败。"
    fi
    
    log_info "Go 版本: $(go version)"
}

# --- 步骤 2：创建 Go 代码 (v6.2) ---
create_go_file() {
    log_info "正在创建 Go 源代码 (main.go)..."
    mkdir -p "$PROJECT_PATH"
    
    # 使用 'EOF' (带引号) 来防止 shell 扩展 $ 和 ` 字符
    cat << 'EOF' > "$PROJECT_PATH/main.go"
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json" // 用于 config.json
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath" // 用于获取可执行文件路径
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/process" // 用于获取 CPU
	"github.com/vishvananda/netlink"
	"golang.org/x/term"
)

var (
	config            Config
	stats             Stats
	ipv6Pool          []net.IP
	poolLock          sync.RWMutex
	backgroundRunning int32
	backgroundAdded   int64
	connLogs          []*ConnLog
	connLogsLock      sync.RWMutex
	maxLogs           = 100

	// 网络相关缓存
	iface     netlink.Link
	prefixIP  net.IP
	prefixNet *net.IPNet

	// 配置文件路径
	configFilePath string
)

// JSON 标签，用于保存到 config.json
type Config struct {
	Port        string `json:"port"`
	WebPort     string `json:"web_port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	IPv6Prefix  string `json:"ipv6_prefix"`
	Interface   string `json:"interface"`
	InitialPool int    `json:"initial_pool"`
	TargetPool  int    `json:"target_pool"`
}

type Stats struct {
	TotalConns, ActiveConns, SuccessConns, FailedConns int64
	TimeoutConns      int64
	PoolSize          int64
	StartTime         time.Time
	TotalDuration     int64 // (原子操作)
	CurrentCPUPercent int64 // (原子操作, 值为 % * 100, 例如 12.5% 存为 1250)
}

type ConnLog struct {
	Time     string `json:"time"`
	ClientIP string `json:"client_ip"`
	Target   string `json:"target"`
	IPv6     string `json:"ipv6"`
	Status   string `json:"status"`
	Duration string `json:"duration"`
}

// 交互式助手：读取用户选择 (1-N)
func readUserChoice(maxChoice int) int {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("请输入您的选择 (1-%d): ", maxChoice)
		text, _ := reader.ReadString('\n')
		choice, err := strconv.Atoi(strings.TrimSpace(text))
		if err != nil || choice < 1 || choice > maxChoice {
			log.Printf("❌ 无效输入，请输入 1 到 %d 之间的数字。", maxChoice)
			continue
		}
		return choice
	}
}

// 交互式助手：读取用户输入的数字
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
			log.Printf("❌ 无效输入，请输入一个有效的正整数。")
			continue
		}
		return val
	}
}

// 交互式助手：读取用户输入的字符串
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

// 交互式助手：读取密码 (不回显)
func readUserPassword(prompt string, defaultValue string) string {
	fmt.Printf("%s (默认 %s): ", prompt, defaultValue)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()

	if err != nil {
		log.Printf("⚠️ 无法安全读取密码, 将使用明文输入...: %v", err)
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

// 交互式选择网卡
func selectInterface() (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("无法列出网卡: %v", err)
	}

	var validLinks []netlink.Link
	for _, link := range links {
		if link.Attrs().Flags&net.FlagUp != 0 && link.Attrs().Flags&net.FlagLoopback == 0 {
			validLinks = append(validLinks, link)
		}
	}

	if len(validLinks) == 0 {
		return nil, errors.New("未找到任何处于 'UP' 状态的非环回网卡")
	}

	log.Println("🔎 发现以下可用网卡:")
	for i, link := range validLinks {
		log.Printf("  %d: %s", i+1, link.Attrs().Name)
	}

	choice := readUserChoice(len(validLinks))
	return validLinks[choice-1], nil
}

// 交互式选择 IPv6 前缀
func selectIPv6Prefix(iface netlink.Link) (string, error) {
	addrs, err := netlink.AddrList(iface, netlink.FAMILY_V6)
	if err != nil {
		return "", fmt.Errorf("无法获取网卡 %s 的地址: %v", iface.Attrs().Name, err)
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
		log.Printf("⚠️ 在 %s 上未自动检测到 Global IPv6 /64 网段。", iface.Attrs().Name)
		log.Println("请输入您的 /64 前缀 (例如: 2402:1f00:800d:bd00):")
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		prefix := strings.TrimSpace(text)
		if prefix == "" {
			return "", errors.New("前缀不能为空")
		}
		return prefix, nil
	}

	var validPrefixes []string
	for prefix := range prefixMap {
		validPrefixes = append(validPrefixes, prefix)
	}

	log.Printf("🔎 在 %s 上发现以下 IPv6 /64 前缀:", iface.Attrs().Name)
	for i, prefix := range validPrefixes {
		log.Printf("  %d: %s", i+1, prefix)
	}

	choice := readUserChoice(len(validPrefixes))
	return validPrefixes[choice-1], nil
}

// 运行交互式设置向导
func runInteractiveSetup() error {
	log.Println("--- 基础设置 ---")
	config.Port = readUserString("请输入代理端口", "1080")
	config.WebPort = readUserString("请输入 Web 面板端口", "8080")
	config.Username = readUserString("请输入代理用户名", "proxy")
	config.Password = readUserPassword("请输入代理密码", "proxy")
	log.Printf("✅ 基础配置完成")

	log.Println("")
	log.Println("--- 网络设置 ---")
	selectedIface, err := selectInterface()
	if err != nil {
		return fmt.Errorf("❌ 网卡选择失败: %v", err)
	}
	config.Interface = selectedIface.Attrs().Name
	log.Printf("✅ 已选择网卡: %s", config.Interface)

	selectedPrefix, err := selectIPv6Prefix(selectedIface)
	if err != nil {
		return fmt.Errorf("❌ IPv6 前缀选择失败: %v", err)
	}
	config.IPv6Prefix = selectedPrefix
	log.Printf("✅ 已选择 IPv6 /64 前缀: %s", config.IPv6Prefix)

	log.Println("")
	log.Println("--- IP 池设置 ---")
	config.InitialPool = readUserInt("请输入初始池大小", 10000)
	config.TargetPool = readUserInt("请输入目标池大小", 100000)

	if config.TargetPool < config.InitialPool {
		log.Printf("⚠️ 目标池 (%d) 小于初始池 (%d)，已自动设置为 %d", config.TargetPool, config.InitialPool, config.InitialPool)
		config.TargetPool = config.InitialPool
	}
	log.Printf("✅ 初始池: %d, 目标池: %d", config.InitialPool, config.TargetPool)
	return nil
}

// 保存配置到 config.json
func saveConfigToFile() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("无法序列化配置: %v", err)
	}
	return os.WriteFile(configFilePath, data, 0644)
}

// 从 config.json 加载配置
func loadConfigFromFile() error {
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		return fmt.Errorf("找不到配置文件 %s。请先以交互模式运行一次 (sudo ./ipv6-proxy) 来生成配置", configFilePath)
	}

	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return fmt.Errorf("无法读取配置文件 %s: %v", configFilePath, err)
	}
	return json.Unmarshal(data, &config)
}

// --- 后续代码 ---

func generateRandomIP() net.IP {
	ip := make(net.IP, 16)
	copy(ip, prefixIP)
	if _, err := rand.Read(ip[8:]); err != nil {
		log.Printf("⚠️ crypto/rand 读取失败: %v, 回退到 math/rand", err)
		binary.BigEndian.PutUint64(ip[8:], mrand.Uint64())
	}
	return ip
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
}

func initIPv6Pool() error {
	log.Printf("🚀 初始化 IPv6 池: %d 个", config.InitialPool)
	if config.InitialPool == 0 {
		log.Printf("✅ 初始池为 0，跳过初始化。")
		return nil
	}

	success := 0
	startTime := time.Now()

	for i := 0; i < config.InitialPool; i++ {
		ip := generateRandomIP()
		if addIPv6(ip) == nil {
			poolLock.Lock()
			ipv6Pool = append(ipv6Pool, ip)
			poolLock.Unlock()
			success++
		}

		if (i+1)%100 == 0 || (i+1) == config.InitialPool {
			percent := float64(i+1) / float64(config.InitialPool) * 100
			fmt.Printf("\r   进度: %d/%d (%.0f%%) ", i+1, config.InitialPool, percent)
		}
	}
	fmt.Println()

	duration := time.Since(startTime)
	atomic.StoreInt64(&stats.PoolSize, int64(success))
	log.Printf("✅ 初始化完成: %d 个 (耗时: %.2fs)", success, duration.Seconds())

	if success == 0 {
		return fmt.Errorf("所有 IPv6 添加失败。请检查前缀 '%s' 是否正确，以及是否以 root 权限运行", config.IPv6Prefix)
	}
	if config.TargetPool > success {
		atomic.StoreInt32(&backgroundRunning, 1)
		go backgroundAddTask()
	}
	return nil
}

func backgroundAddTask() {
	defer atomic.StoreInt32(&backgroundRunning, 0)
	log.Printf("🔄 后台任务: 添加到目标池 %d", config.TargetPool)
	for {
		currentTargetPool := config.TargetPool
		currentSize := int(atomic.LoadInt64(&stats.PoolSize))

		if currentSize >= currentTargetPool {
			break
		}
		if atomic.LoadInt32(&backgroundRunning) == 0 {
			break
		}

		ip := generateRandomIP()
		if addIPv6(ip) == nil {
			poolLock.Lock()
			ipv6Pool = append(ipv6Pool, ip)
			poolLock.Unlock()
			atomic.AddInt64(&stats.PoolSize, 1)
			atomic.AddInt64(&backgroundAdded, 1)
		}

		if atomic.LoadInt64(&backgroundAdded)%10000 == 0 {
			log.Printf("📈 后台进度: %d/%d", atomic.LoadInt64(&stats.PoolSize), currentTargetPool)
		}
		time.Sleep(1 * time.Millisecond)
	}
	log.Printf("✅ 后台完成: %d 个", atomic.LoadInt64(&stats.PoolSize))
}

func getRandomIP() net.IP {
	poolLock.RLock()
	defer poolLock.RUnlock()
	if len(ipv6Pool) == 0 {
		return nil
	}
	return ipv6Pool[mrand.Intn(len(ipv6Pool))]
}

func checkAuth(user, pass string) bool {
	return user == config.Username && pass == config.Password
}

func transfer(dst net.Conn, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer dst.Close()

	buf := make([]byte, 32*1024)
	for {
		src.SetReadDeadline(time.Now().Add(120 * time.Second))
		nr, er := src.Read(buf)
		if nr > 0 {
			dst.SetWriteDeadline(time.Now().Add(120 * time.Second))
			if _, ew := dst.Write(buf[0:nr]); ew != nil {
				break
			}
		}
		if er != nil {
			break
		}
	}
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
		conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\nConnection: close\r\n\r\n"))
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}
	if method != "CONNECT" {
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n"))
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
			clientConn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n"))
		}
		atomic.AddInt64(&stats.FailedConns, 1)
		return
	}

	ipv6String := ip.String()
	localAddr := &net.TCPAddr{IP: ip}
	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   15 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	remoteConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		status := "❌ 失败"
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			status = "⏱️ 超时"
			atomic.AddInt64(&stats.TimeoutConns, 1)
		}
		addConnLog(clientIP, target, ipv6String, status, time.Since(startTime))
		if isSocks {
			clientConn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		} else {
			clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
		}
		atomic.AddInt64(&stats.FailedConns, 1)
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
		if err != io.EOF {
			// log.Printf("Pre-read error: %v", err)
		}
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

func statsCPURoutine() {
	time.Sleep(3 * time.Second)

	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		log.Printf("⚠️ 无法获取当前进程 (pid: %d) 来监控 CPU: %v", os.Getpid(), err)
		return
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		percent, err := p.CPUPercent()
		if err == nil {
			atomic.StoreInt64(&stats.CurrentCPUPercent, int64(percent*100))
		}
	}
}

func statsRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("📊 活跃:%d 总计:%d 成功:%d 失败:%d 超时:%d 池:%d",
			atomic.LoadInt64(&stats.ActiveConns),
			atomic.LoadInt64(&stats.TotalConns),
			atomic.LoadInt64(&stats.SuccessConns),
			atomic.LoadInt64(&stats.FailedConns),
			atomic.LoadInt64(&stats.TimeoutConns),
			atomic.LoadInt64(&stats.PoolSize))
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
		avgDurationNs := atomic.LoadInt64(&stats.TotalDuration)
		avgDurationMs = float64(avgDurationNs) / float64(successConns) / float64(time.Millisecond)
	}

	cpuPercent := float64(atomic.LoadInt64(&stats.CurrentCPUPercent)) / 100.0

	data := map[string]interface{}{
		"active":       atomic.LoadInt64(&stats.ActiveConns),
		"total":        total,
		"success":      successConns,
		"failed":       atomic.LoadInt64(&stats.FailedConns),
		"timeout":      atomic.LoadInt64(&stats.TimeoutConns),
		"pool":         currentPool,
		"target":       targetPool,
		"progress":     progress,
		"bg_running":   atomic.LoadInt32(&backgroundRunning) == 1,
		"bg_added":     atomic.LoadInt64(&backgroundAdded),
		"qps":          qps,
		"uptime":       fmt.Sprintf("%dd %dh %dm", int(uptime.Hours())/24, int(uptime.Hours())%24, int(uptime.Minutes())%60),
		"avg_duration": avgDurationMs,
		"cpu_percent":  cpuPercent,
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

func handleAPIPoolResize(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target int `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"请求无效"}`, http.StatusBadRequest)
		return
	}

	if req.Target < 100 {
		http.Error(w, `{"error":"目标值至少100"}`, http.StatusBadRequest)
		return
	}

	config.TargetPool = req.Target
	log.Printf("🎯 调整目标池: %d", req.Target)

	if atomic.LoadInt32(&backgroundRunning) == 0 && atomic.LoadInt64(&stats.PoolSize) < int64(req.Target) {
		atomic.StoreInt32(&backgroundRunning, 1)
		go backgroundAddTask()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": fmt.Sprintf("已设置目标: %d", req.Target)})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile("index.html")
	if err != nil {
		log.Printf("❌ 错误: 找不到 index.html 文件: %v", err)
		http.Error(w, "index.html not found. Make sure it is in the same directory.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(html)
}

func startWebServer() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/stats", handleAPIStats)
	http.HandleFunc("/api/logs", handleAPILogs)
	http.HandleFunc("/api/pool/resize", handleAPIPoolResize)
	log.Printf("🌐 Web 面板: http://0.0.0.0:%s", config.WebPort)
	go func() {
		if err := http.ListenAndServe(":"+config.WebPort, nil); err != nil {
			log.Printf("⚠️ Web 服务器启动失败: %v", err)
		}
	}()
}

func main() {
	log.Printf("╔════════════════════════════════════════════╗")
	log.Printf("║  IPv6 代理 + Web 面板 v6.2 (修复版)  ║")
	log.Printf("╚════════════════════════════════════════════╝")
	log.Printf("")

	stats.StartTime = time.Now()

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("❌ 无法获取可执行文件路径: %v", err)
	}
	configFilePath = filepath.Join(filepath.Dir(exePath), "config.json")

	isInteractive := term.IsTerminal(int(syscall.Stdin))

	if isInteractive {
		log.Println("--- 欢迎使用交互式设置向导 ---")
		if err := runInteractiveSetup(); err != nil {
			log.Fatalf("❌ 向导失败: %v", err)
		}
		if err := saveConfigToFile(); err != nil {
			log.Fatalf("❌ 保存配置到 %s 失败: %v", configFilePath, err)
		}
		log.Printf("✅ 配置已保存到 %s", configFilePath)
	} else {
		log.Printf("🔄 以服务模式运行，正在从 %s 加载配置...", configFilePath)
		if err := loadConfigFromFile(); err != nil {
			log.Fatalf("❌ 无法加载配置: %v", err)
		}
		log.Println("✅ 配置加载成功")
	}

	// --- 启动流程 ---

	prefixIP, prefixNet, err = net.ParseCIDR(config.IPv6Prefix + "::/64")
	if err != nil {
		log.Fatalf("❌ 无法解析 IPv6 前缀: %v", err)
	}
	iface, err = netlink.LinkByName(config.Interface)
	if err != nil {
		log.Fatalf("❌ 无法找到网卡 '%s': %v", config.Interface, err)
	}

	log.Printf("")
	log.Printf("--- 最终配置 ---")
	log.Printf("代理: %s | Web: %s", config.Port, config.WebPort)
	log.Printf("用户: %s | 密码: [已隐藏]", config.Username)
	log.Printf("IPv6: %s::/64 | 网卡: %s", config.IPv6Prefix, config.Interface)
	log.Printf("初始池: %d | 目标池: %d", config.InitialPool, config.TargetPool)
	log.Printf("------------------")
	log.Printf("")

	if err := initIPv6Pool(); err != nil {
		log.Fatalf("❌ 初始化失败: %v", err)
	}

	go statsRoutine()
	go statsCPURoutine() // 启动 CPU 监控
	startWebServer()

	listener, err := net.Listen("tcp", ":"+config.Port)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	log.Printf("✅ 服务就绪")
	log.Printf("")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept 失败: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
EOF
}

# --- 步骤 3：创建 HTML 页面 (v6.1) ---
create_html_file() {
    log_info "正在创建前端页面 (index.html)..."
    
    cat << 'EOF' > "$PROJECT_PATH/index.html"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IPv6 代理管理面板</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box
        }

        body {
            font-family: sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 20px
        }

        .container {
            max-width: 1400px;
            margin: 0 auto
        }

        h1 {
            font-size: 28px;
            margin-bottom: 20px;
            color: #60a5fa
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px
        }

        .card {
            background: #1e293b;
            border-radius: 12px;
            padding: 20px
        }

        .card-title {
            font-size: 14px;
            color: #94a3b8;
            margin-bottom: 10px
        }

        .card-value {
            font-size: 32px;
            font-weight: bold;
            color: #60a5fa
        }
        /* 为连接统计卡片调整字体 */
        .card-value-small {
            font-size: 24px;
            font-weight: bold;
            color: #60a5fa
        }
        .card-value-small .success {
            color: #10b981
        }
        .card-value-small .fail {
            color: #ef4444
        }

        .card-sub {
            font-size: 12px;
            color: #64748b;
            margin-top: 5px
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: #334155;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #3b82f6, #60a5fa);
            transition: width .3s
        }

        .section {
            background: #1e293b;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px
        }

        .section-title {
            font-size: 18px;
            margin-bottom: 15px
        }

        table {
            width: 100%;
            border-collapse: collapse
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #334155
        }

        th {
            color: #94a3b8;
            font-size: 14px
        }

        .status-success {
            color: #10b981
        }

        .status-fail {
            color: #ef4444
        }

        .status-timeout {
            color: #f59e0b
        }

        .input-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap
        }

        input[type=number] {
            background: #334155;
            border: 1px solid #475569;
            color: #e2e8f0;
            padding: 8px 12px;
            border-radius: 6px;
            width: 150px
        }

        button {
            background: #3b82f6;
            color: #fff;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer
        }

        button:hover {
            background: #2563eb
        }

        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px
        }

        .badge-success {
            background: #10b98120;
            color: #10b981
        }

        .badge-info {
            background: #3b82f620;
            color: #3b82f6
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🚀 IPv6 代理管理面板 (v6.1)</h1>
    <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));">
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
            <div class="card-title">连接统计 (成功/失败)</div>
            <div class="card-value-small" id="success-fail">
                <span class="success">-</span> / <span class="fail">-</span>
            </div>
            <div class="card-sub">超时: <span id="timeout">-</span></div>
        </div>
        <div class="card">
            <div class="card-title">CPU 占用率</div>
            <div class="card-value" id="cpu-percent">- %</div>
            <div class="card-sub">进程 CPU 占用</div>
        </div>
        <div class="card">
            <div class="card-title">平均连接耗时</div>
            <div class="card-value" id="avg-duration">- ms</div>
            <div class="card-sub">成功连接的平均值</div>
        </div>
        <div class="card">
            <div class="card-title">IPv6 池</div>
            <div class="card-value" id="pool-size">-</div>
            <div class="card-sub">目标: <span id="pool-target">-</span></div>
            <div class="progress-bar">
                <div class="progress-fill" id="pool-progress"></div>
            </div>
        </div>
    </div>
    <div class="section">
        <div class="section-title">📊 IPv6 池管理</div>
        <div class="input-group">
            <label>目标池大小:</label>
            <input type="number" id="new-target" placeholder="100000" min="100" step="1000">
            <button onclick="resizePool()">应用</button>
            <span id="pool-status"></span>
        </div>
    </div>
    <div class="section">
        <div class="section-title">📝 最近连接</div>
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
            <tr>
                <td colspan="6" style="text-align:center;color:#64748b">等待连接...</td>
            </tr>
            </tbody>
        </table>
    </div>
</div>
<script>
    function updateStats() {
        fetch('/api/stats').then(r => r.json()).then(d => {
            document.getElementById('active').textContent = d.active;
            document.getElementById('total').textContent = d.total;
            document.getElementById('qps').textContent = d.qps.toFixed(2);
            
            // 更新 连接统计 卡片
            document.getElementById('success-fail').innerHTML = '<span class="success">' + d.success + '</span> / <span class="fail">' + d.failed + '</span>';
            document.getElementById('timeout').textContent = d.timeout;
            
            // 更新 CPU 卡片
            document.getElementById('cpu-percent').textContent = d.cpu_percent.toFixed(1) + ' %';
            
            // 更新 平均耗时 卡片
            document.getElementById('avg-duration').textContent = d.avg_duration.toFixed(0) + ' ms';

            // 更新 IP 池 卡片
            document.getElementById('pool-size').textContent = d.pool;
            document.getElementById('pool-target').textContent = d.target;
            document.getElementById('pool-progress').style.width = d.progress.toFixed(1) + '%';
            document.getElementById('pool-status').innerHTML = d.bg_running ? '<span class="badge badge-info">后台运行中</span>' : '<span class="badge badge-success">就绪</span>';
        })
    }

    function updateLogs() {
        fetch('/api/logs').then(r => r.json()).then(logs => {
            const table = document.getElementById('logs-table');
            if (logs.length === 0) return;
            table.innerHTML = logs.map(log => '<tr><td>' + log.time + '</td><td>' + log.client_ip + '</td><td>' + log.target + '</td><td>' + log.ipv6 + '</td><td class="' + (log.status.includes('✅') ? 'status-success' : log.status.includes('⏱') ? 'status-timeout' : 'status-fail') + '">' + log.status + '</td><td>' + log.duration + '</td></tr>').join('');
        })
    }

    function resizePool() {
        const v = parseInt(document.getElementById('new-target').value);
        if (!v || v < 100) {
            alert('请输入有效值 (至少100)');
            return
        }
        fetch('/api/pool/resize', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target: v})
        }).then(r => r.json()).then(d => {
            alert(d.message || d.error);
            updateStats()
        })
    }

    setInterval(updateStats, 3000);
    setInterval(updateLogs, 5000);
    updateStats();
    updateLogs();
</script>
</body>
</html>
EOF
}

# --- 步骤 4：编译程序 ---
compile_program() {
    log_info "正在编译程序..."
    cd "$PROJECT_PATH" || log_error "无法进入项目目录 $PROJECT_PATH"
    
    log_info "初始化 Go 模块 (go mod init)..."
    go mod init ipv6-proxy
    
    log_info "下载所有依赖 (go mod tidy)..."
    if ! go mod tidy; then
        log_error "go mod tidy 失败。请检查 Go 版本和网络。"
    fi
    
    log_info "正在编译二进制文件 (go build)..."
    if ! CGO_ENABLED=0 go build -ldflags "-s -w" -o "$GO_BINARY" .; then
        log_error "编译失败。请检查 Go 代码和依赖。"
    fi
    
    log_info "编译完成！程序位于 $PROJECT_PATH/$GO_BINARY"
}

# --- 步骤 5：交互式设置 ---
manual_setup_step() {
    echo -e "\n${YELLOW}======================= 关键步骤：交互式设置 =======================${NC}"
    echo -e "${YELLOW}您需要运行一次程序来生成 'config.json' 配置文件。${NC}"
    echo -e "请按照提示完成所有设置 (端口、密码、网卡、IP池等)。"
    echo -e "\n${GREEN}请立即执行以下命令：${NC}"
    echo -e "cd $PROJECT_PATH && sudo ./$GO_BINARY"
    echo -e "\n${YELLOW}完成设置后，程序会开始运行。当您看到 '✅ 服务就绪' 时，请按 ${RED}Ctrl+C${YELLOW} 停止它。${NC}"
    
    read -p "完成上述步骤后，请按 [Enter] 键继续安装 Systemd 服务..."
    
    if [ ! -f "$PROJECT_PATH/config.json" ]; then
        log_error "未检测到 $PROJECT_PATH/config.json 文件！请确保您已成功运行交互式设置。"
    fi
    log_info "检测到 config.json，继续安装服务。"
}

# --- 步骤 6：创建 Systemd 服务 ---
create_systemd_service() {
    log_info "正在创建 $SERVICE_NAME..."
    
    cat << EOF > "/etc/systemd/system/$SERVICE_NAME"
[Unit]
Description=IPv6 Proxy Service (v6.1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

# 关键：设置正确的工作目录和启动命令
WorkingDirectory=$PROJECT_PATH
ExecStart=$PROJECT_PATH/$GO_BINARY

# 必需：允许程序修改网络接口
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    log_info "创建 Systemd 文件成功。"
}

# --- 步骤 7：自检 Web 面板 ---
self_test() {
    log_info "正在执行自检 (测试 Web 面板)..."
    
    # 从 JSON 中提取 Web 端口
    WEB_PORT=$(grep -oP '"web_port": "\K[^"]+' "$PROJECT_PATH/config.json")
    if [ -z "$WEB_PORT" ]; then
        log_warn "无法从 config.json 中读取 Web 端口。跳过自检。"
        return
    fi
    
    log_info "Web 端口为: $WEB_PORT。正在启动服务以进行测试..."
    
    # 临时启动服务
    systemctl daemon-reload
    systemctl start "$SERVICE_NAME"
    
    log_info "等待 5 秒让服务启动..."
    sleep 5
    
    log_info "使用 curl 测试 http://127.0.0.1:$WEB_PORT ..."
    if curl -s --head "http://127.0.0.1:$WEB_PORT" | grep -q "200 OK"; then
        log_info "✅ 自检成功！Web 面板 (Wab) 响应正常。"
    else
        log_warn "⚠️ 自检失败。无法访问 Web 面板。请检查端口 $WEB_PORT 或防火墙。"
        log_warn "服务仍会继续运行，请手动检查。"
    fi
}

# --- 步骤 8：启动服务并显示命令 ---
start_and_show_commands() {
    log_info "设置服务开机自启 (systemctl enable)..."
    systemctl enable "$SERVICE_NAME"
    
    # 服务已经在自检时启动了，这里确保它是 running 状态
    systemctl restart "$SERVICE_NAME"
    
    echo -e "\n${GREEN}===================================================================${NC}"
    echo -e "${GREEN}🎉 恭喜！IPv6 代理已安装并默认在后台运行！${NC}"
    echo -e "您的 Web 面板 (Wab) 应该在您设置的端口上可用。"
    echo -e "\n${YELLOW}--- 常用管理命令 ---${NC}"
    echo -e "启动服务: ${GREEN}sudo systemctl start $SERVICE_NAME${NC}"
    echo -e "停止服务: ${GREEN}sudo systemctl stop $SERVICE_NAME${NC}"
    echo -e "重启服务: ${GREEN}sudo systemctl restart $SERVICE_NAME${NC}"
    echo -e "查看状态: ${GREEN}sudo systemctl status $SERVICE_NAME${NC}"
    echo -e "查看日志: ${GREEN}sudo journalctl -u $SERVICE_NAME -f${NC}"
    echo -e "\n配置文件位于: ${GREEN}$PROJECT_PATH/config.json${NC}"
    echo -e "如果需要修改配置, 请编辑该文件, 然后运行 'sudo systemctl restart $SERVICE_NAME'"
    echo -e "${GREEN}===================================================================${NC}"
}

# --- 主函数 ---
main() {
    check_root
    install_deps
    create_go_file
    create_html_file
    compile_program
    manual_setup_step
    create_systemd_service
    self_test
    start_and_show_commands
}

# --- 运行 ---
main
