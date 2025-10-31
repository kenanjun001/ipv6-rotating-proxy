#!/bin/bash
#
# IPv6 代理 (v6.5) 一键安装脚本
# 自动清理、安装正确的 Go 1.21.5、修复 index.html CWD 错误、
# 新增 12h 日志清理 & 24h IP 轮换、
# 编译、安装到 /opt/ipv6-proxy，并自动引导配置和启动。
#

# --- 配置 ---
INSTALL_DIR="/opt/ipv6-proxy"
BUILD_DIR="/root/ipv6-proxy-build"
GO_VERSION="1.21.5"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"
# 确保新 Go 的路径被使用
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=/usr/local/go/bin:$PATH:$GOPATH/bin


# --- 脚本开始 ---
set -e # 遇到错误立即退出

# 检查是否为 root
if [ "$(id -u)" -ne 0 ]; then
  echo "❌ 错误：此脚本必须以 root 权限运行。"
  echo "请尝试使用: sudo ./install.sh"
  exit 1
fi

echo "============================================="
echo "=== IPv6 代理 (v6.5) 正在开始安装... ==="
echo "============================================="
echo "安装目录: $INSTALL_DIR"
echo ""

# --- 步骤 1: 彻底清理旧服务和文件 ---
echo "--- 步骤 1: 正在清理旧的服务和文件... ---"
systemctl stop ipv6-proxy.service >/dev/null 2>&1 || true
systemctl disable ipv6-proxy.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/ipv6-proxy.service
# 清理所有已知目录
rm -rf /opt/ipv6-proxy
rm -rf /home/ubuntu/geminiip
rm -rf /root/ip
rm -rf "$BUILD_DIR" # 清理临时编译目录
systemctl daemon-reload
echo "✅ 旧服务和文件清理完毕。"
echo ""

# --- 步骤 2: 安装依赖 (wget 和 最新的 Go) ---
echo "--- 步骤 2: 正在安装依赖 (wget 和 Go $GO_VERSION)... ---"
apt-get update >/dev/null
apt-get install -y wget
# 移除旧的 apt-get go
apt-get remove -y golang-go >/dev/null 2>&1 || true
rm -rf /usr/lib/go # 清理旧的 GOROOT

# 下载并安装 Go 1.21.5
if [ ! -d "/usr/local/go" ] || ! /usr/local/go/bin/go version | grep -q "$GO_VERSION"; then
  echo "正在下载 Go $GO_VERSION..."
  wget -q "$GO_URL" -O "/tmp/$GO_TAR"
  echo "正在解压 Go..."
  tar -C /usr/local -xzf "/tmp/$GO_TAR"
  rm "/tmp/$GO_TAR"
else
  echo "Go $GO_VERSION 已安装。"
fi

# 确保 shell 知道新的 Go 路径
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=/usr/local/go/bin:$PATH:$GOPATH/bin
echo "✅ Go 环境已就绪。 (`go version`)"
/usr/local/go/bin/go version # 验证版本
echo ""

# --- 步骤 3: 创建项目文件 (v6.5 代码) ---
echo "--- 步骤 3: 正在创建 v6.5 源代码到 $BUILD_DIR ... ---"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# 创建 main.go (v6.5 - 修复 CWD 和 io.File, 新增 12h/24h 任务)
cat << 'EOF' > main.go
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
	"golang.org/x/term" // 用于安全读取密码
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
    // !!! 修复 CWD 错误：存储 index.html 的路径
    indexHTMLPath string
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
	TotalDuration     int64 // (原子操作, 纳秒)
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

// 内部函数：添加 IP，带进度
func populateIPPool(numToAdd int) ([]net.IP, int) {
	newIPs := make([]net.IP, 0, numToAdd)
	success := 0
	startTime := time.Now()

	for i := 0; i < numToAdd; i++ {
		ip := generateRandomIP()
		if addIPv6(ip) == nil {
			newIPs = append(newIPs, ip)
			success++
		}

		if (i+1)%100 == 0 || (i+1) == numToAdd {
			percent := float64(i+1) / float64(numToAdd) * 100
			fmt.Printf("\r   进度: %d/%d (%.0f%%) ", i+1, numToAdd, percent)
		}
	}
	fmt.Println()
	duration := time.Since(startTime)
	log.Printf("✅ 添加了 %d 个 IP (耗时: %.2fs)", success, duration.Seconds())
	return newIPs, success
}

func initIPv6Pool() error {
	log.Printf("🚀 初始化 IPv6 池: %d 个", config.InitialPool)
	if config.InitialPool == 0 {
		log.Printf("✅ 初始池为 0，跳过初始化。")
		return nil
	}

	newIPs, success := populateIPPool(config.InitialPool)
	
	poolLock.Lock()
	ipv6Pool = newIPs
	poolLock.Unlock()
	
	atomic.StoreInt64(&stats.PoolSize, int64(success))

	if success == 0 {
		return fmt.Errorf("所有 IPv6 添加失败。请检查前缀 '%s' 是否正确，以及是否以 root 权限运行", config.IPv6Prefix)
	}
	return nil
}

func backgroundAddTask() {
	defer atomic.StoreInt32(&backgroundRunning, 0)
	
	// 确保我们只在需要时运行
	if config.TargetPool <= config.InitialPool {
		log.Printf("ℹ️ 目标池不大于初始池，后台添加任务跳过。")
		return
	}
	
	log.Printf("🔄 后台任务: 添加到目标池 %d", config.TargetPool)
	
	// 死循环，直到被 stop (backgroundRunning=0) 或达到目标
	for {
		if atomic.LoadInt32(&backgroundRunning) == 0 {
			log.Printf("ℹ️ 后台任务被停止。")
			break 
		}

		currentSize := int(atomic.LoadInt64(&stats.PoolSize))
		if currentSize >= config.TargetPool {
			log.Printf("✅ 后台完成: %d 个", currentSize)
			break // 达到目标
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
			log.Printf("📈 后台进度: %d/%d", atomic.LoadInt64(&stats.PoolSize), config.TargetPool)
		}
		time.Sleep(1 * time.Millisecond)
	}
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
		// 修复：io.File -> io.ReadFull
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

// 新增：12 小时日志清理
func logClearRoutine() {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("🧹 正在执行 12 小时日志自动清理...")
		connLogsLock.Lock()
		connLogs = []*ConnLog{}
		connLogsLock.Unlock()
		log.Printf("✅ 12 小时日志已自动清理")
	}
}

// 新增：24 小时 IP 池轮换
func ipRotationRoutine() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		log.Printf("🔄 正在执行 24 小时 IP 池轮换 (安全模式)...")
		
		// 1. 停止后台任务（如果它在运行）
		atomic.StoreInt32(&backgroundRunning, 0)
		time.Sleep(1 * time.Second) // 等待任务退出

		// 2. 准备新池 (使用 InitialPool 大小)
		log.Printf("   ...正在生成 %d 个新 IP...", config.InitialPool)
		newIPs, success := populateIPPool(config.InitialPool)
		if success == 0 {
			log.Printf("❌ 24 小时轮换失败：无法添加任何新 IP。")
			continue // 跳过此次轮换
		}

		// 3. 安全替换
		poolLock.Lock()
		ipv6Pool = newIPs
		poolLock.Unlock()
		
		atomic.StoreInt64(&stats.PoolSize, int64(success))
		log.Printf("✅ IP 池轮换完毕。新池中有 %d 个 IP。", success)
		
		// 4. 重启后台任务（如果需要）
		if config.TargetPool > success {
			atomic.StoreInt32(&backgroundRunning, 1)
			go backgroundAddTask()
			log.Printf("   ...已重启后台任务以填充到 %d。", config.TargetPool)
		}
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

// 修复 CWD 错误：使用 indexHTMLPath
func handleIndex(w http.ResponseWriter, r *http.Request) {
	html, err := os.ReadFile(indexHTMLPath)
	if err != nil {
		log.Printf("❌ 错误: 找不到 index.html 文件 (路径: %s): %v", indexHTMLPath, err)
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
	log.Printf("║  IPv6 代理 + Web 面板 v6.5 (终极版)  ║")
	log.Printf("╚════════════════════════════════════════════╝")
	log.Printf("")

	stats.StartTime = time.Now()

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("❌ 无法获取可执行文件路径: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// 修复 CWD 错误：设置 config 和 index 的绝对路径
	configFilePath = filepath.Join(exeDir, "config.json")
	indexHTMLPath = filepath.Join(exeDir, "index.html")

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

	// 启动所有后台任务
	atomic.StoreInt32(&backgroundRunning, 1) // 允许后台任务运行
	go backgroundAddTask() // 启动 IP 池填充任务
	go statsRoutine()
	go statsCPURoutine() // 启动 CPU 监控
	go logClearRoutine() // 启动 12h 日志清理
	go ipRotationRoutine() // 启动 24h IP 轮换
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

# 创建 index.html (v6.2)
cat << 'EOF' > index.html
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
    <h1>🚀 IPv6 代理管理面板 (v6.5)</h1>
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
            if (!logs || logs.length === 0) return;
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

echo "✅ 源代码和网页文件创建完毕。"
echo ""

# --- 步骤 4: 编译程序 ---
echo "--- 步骤 4: 正在编译程序 (可能需要几分钟)... ---"
# 使用新安装的 Go (v1.21.5)
/usr/local/go/bin/go mod init ipv6-proxy >/dev/null
/usr/local/go/bin/go mod tidy >/dev/null
echo "正在编译，请稍候... (这会下载 gopsutil, netlink, term 等库)"
CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags "-s -w" -o ipv6-proxy .
echo "✅ 程序 'ipv6-proxy' 编译完毕！"
echo ""

# --- 步骤 5: 将文件移动到 /opt/ipv6-proxy ---
echo "--- 步骤 5: 正在将文件安装到 $INSTALL_DIR ... ---"
mkdir -p "$INSTALL_DIR"
mv ipv6-proxy "$INSTALL_DIR/"
mv index.html "$INSTALL_DIR/"
# 编译完后删除临时目录
cd /
rm -rf "$BUILD_DIR"
echo "✅ 文件已安装到 $INSTALL_DIR"
echo ""

# --- 步骤 6: 创建 systemd 服务文件 ---
echo "--- 步骤 6: 正在创建 systemd 服务... ---"

# 注意：这里我们使用了 $INSTALL_DIR 变量
cat << EOF > /etc/systemd/system/ipv6-proxy.service
[Unit]
Description=IPv6 Proxy Service v6.5 (Gemini)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

# 关键：设置正确的工作目录和启动命令
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/ipv6-proxy

# 需要 CAP_NET_ADMIN 权限来修改 IP 地址
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN

Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "✅ systemd 服务 'ipv6-proxy.service' 创建完毕。"
echo ""

# --- 步骤 7: 自动引导安装 + 启动 ---
echo "============================================="
echo "🎉🎉🎉 恭喜！安装已全部完成！ 🎉🎉🎉"
echo "============================================="
echo ""
echo "您现在需要执行【最后两个步骤】来启动服务："
echo ""
echo "1. 【首次配置】(自动引导安装)"
echo "   脚本现在将自动为您运行首次配置向导。"
echo "   请回答所有问题 (端口, 密码, 网卡, IP池等)..."
echo ""

# 自动运行交互式向导
# 我们用 '|| true' 来防止用户按 Ctrl+C 导致 'set -e' 终止脚本
sudo $INSTALL_DIR/ipv6-proxy || true

# ^^^^
# 脚本会在这里暂停，等待用户完成交互式设置。
# 用户回答完所有问题，看到 "✅ 服务就绪" 后，按 Ctrl+C 退出。

echo ""
echo "---------------------------------------------"
echo "✅ 交互式配置完成 (config.json 已生成)。"
echo "---------------------------------------------"
echo ""
echo "2. 【启动后台服务】"
echo "   现在，我们将为您启动后台服务并设置开机自启："
echo ""

sudo systemctl enable ipv6-proxy
sudo systemctl start ipv6-proxy

echo ""
echo "✅ 服务已在后台启动！"
echo "您可以使用 'sudo systemctl status ipv6-proxy' 来检查状态。"
echo "您的 Web 面板 (config.json中配置的) 应该可以访问了。"
echo ""
