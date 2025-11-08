#!/bin/bash
#
# IPv6 代理 v8.1.1 多前缀智能版 完全集成安装脚本
# v8.1.1 新增：支持空格分隔的前缀选择（1 2 3 或 1,2,3 都可以）
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
echo "=== IPv6 代理 v8.1 多前缀智能版 ==="
echo "============================================="
echo ""

# --- 智能处理dpkg锁 ---
handle_apt_locks() {
    local max_wait=60
    local waited=0
    local need_wait=false
    
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
       fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
       fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
        need_wait=true
    fi
    
    if [ "$need_wait" = true ]; then
        print_warning "检测到系统正在进行其他操作"
        echo "正在智能处理..."
        
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
        
        print_info "自动清理系统锁..."
        killall apt 2>/dev/null || true
        killall apt-get 2>/dev/null || true
        killall dpkg 2>/dev/null || true
        killall unattended-upgr 2>/dev/null || true
        
        sleep 2
        
        rm -f /var/lib/apt/lists/lock
        rm -f /var/cache/apt/archives/lock
        rm -f /var/lib/dpkg/lock*
        rm -f /var/lib/dpkg/lock-frontend
        
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

handle_apt_locks

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

apt-get remove -y golang-go >/dev/null 2>&1 || true

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

	// 多前缀相关变量
	autoSwitchEnabled  int32
	nextSwitchTime     time.Time
	nextSwitchTimeLock sync.RWMutex

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
	Port                string       `json:"port"`
	WebPort             string       `json:"web_port"`
	WebUsername         string       `json:"web_username"`
	WebPassword         string       `json:"web_password"`
	Username            string       `json:"username"`
	Password            string       `json:"password"`
	IPv6Prefix          string       `json:"ipv6_prefix"`          // 保留用于向后兼容
	IPv6Prefixes        []string     `json:"ipv6_prefixes"`        // 新增：多前缀列表
	ActivePrefixIndex   int          `json:"active_prefix_index"`  // 当前激活的前缀索引
	AutoSwitchPrefix    bool         `json:"auto_switch_prefix"`   // 是否自动切换前缀
	SwitchIntervalHours int          `json:"switch_interval_hours"` // 切换间隔（小时）
	Interface           string       `json:"interface"`
	InitialPool         int          `json:"initial_pool"`
	TargetPool          int          `json:"target_pool"`
	AutoRotate          bool         `json:"auto_rotate"`
	AutoRotateHours     int          `json:"auto_rotate_hours"`
	AutoClean           bool         `json:"auto_clean"`
	Ports               []PortConfig `json:"ports"`
}

type Stats struct {
	TotalConns, ActiveConns, SuccessConns, FailedConns int64
	TimeoutConns         int64
	PoolSize             int64
	StartTime            time.Time
	TotalDuration        int64
	ProcessCPUPercent    int64
	SystemCPUPercent     int64
	TotalBytesRecv       int64
	TotalBytesSent       int64
	CurrentRecvRate      int64
	CurrentSendRate      int64
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

type PortConfig struct {
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ===== 多前缀相关结构 =====

type PrefixInfo struct {
	Prefix    string `json:"prefix"`
	Index     int    `json:"index"`
	IsActive  bool   `json:"is_active"`
	IsValid   bool   `json:"is_valid"`
	ErrorMsg  string `json:"error_msg,omitempty"`
}

type PrefixStatus struct {
	Prefixes            []PrefixInfo `json:"prefixes"`
	ActiveIndex         int          `json:"active_index"`
	AutoSwitchEnabled   bool         `json:"auto_switch_enabled"`
	SwitchIntervalHours int          `json:"switch_interval_hours"`
	NextSwitchTime      string       `json:"next_switch_time"`
	SecondsUntilSwitch  int64        `json:"seconds_until_switch"`
}

// 用于自动检测的结构
type DetectedPrefix struct {
	Prefix     string
	Interface  string
	SampleIP   string
	PrefixLen  int
}

// ===== 辅助函数 =====

// 检测系统中所有可用的IPv6前缀
func detectIPv6Prefixes() []DetectedPrefix {
	var detected []DetectedPrefix
	seenPrefixes := make(map[string]bool)

	links, err := netlink.LinkList()
	if err != nil {
		return detected
	}

	for _, link := range links {
		// 跳过 loopback 和 down 状态的接口
		if link.Attrs().Flags&net.FlagLoopback != 0 {
			continue
		}
		if link.Attrs().Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip := addr.IPNet.IP
			
			// 跳过链路本地地址 (fe80::)
			if ip.IsLinkLocalUnicast() {
				continue
			}
			
			// 跳过本地回环地址
			if ip.IsLoopback() {
				continue
			}
			
			// 只处理全局单播地址
			if !ip.IsGlobalUnicast() {
				continue
			}

			// 获取前缀长度
			ones, bits := addr.IPNet.Mask.Size()
			
			// 只检测真正的网络前缀，不要单个地址
			// IPv6网络前缀通常是 /48 到 /64
			// /128 是单个地址，跳过
			if ones >= 120 {
				continue
			}
			
			// 前缀长度必须在合理范围内
			if ones < 32 || ones > 80 {
				continue
			}

			// 生成标准前缀字符串（转换为/64如果是其他长度）
			// 对于大多数情况，我们使用/64前缀
			standardPrefixLen := 64
			if ones <= 64 {
				standardPrefixLen = ones
			}
			
			// 创建标准前缀（/64或原始前缀长度）
			standardMask := net.CIDRMask(standardPrefixLen, bits)
			standardPrefixIP := ip.Mask(standardMask)
			standardPrefixStr := fmt.Sprintf("%s/%d", standardPrefixIP, standardPrefixLen)

			// 去重
			if seenPrefixes[standardPrefixStr] {
				continue
			}
			seenPrefixes[standardPrefixStr] = true

			detected = append(detected, DetectedPrefix{
				Prefix:    standardPrefixStr,
				Interface: link.Attrs().Name,
				SampleIP:  ip.String(),
				PrefixLen: standardPrefixLen,
			})
		}
	}

	return detected
}

// 解析用户的选择输入
func parseSelection(input string, maxNum int) []int {
	var indices []int
	seenIndices := make(map[int]bool)

	input = strings.ToLower(strings.TrimSpace(input))
	
	// 处理 "all" 情况
	if input == "all" || input == "a" {
		for i := 0; i < maxNum; i++ {
			indices = append(indices, i)
		}
		return indices
	}

	// 统一处理：将空格、制表符替换为逗号，方便统一解析
	input = strings.ReplaceAll(input, " ", ",")
	input = strings.ReplaceAll(input, "\t", ",")
	// 清理连续的逗号
	for strings.Contains(input, ",,") {
		input = strings.ReplaceAll(input, ",,", ",")
	}
	input = strings.Trim(input, ",")

	// 分割逗号
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		// 处理范围 (例如: 1-3)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil {
					for i := start; i <= end; i++ {
						if i >= 1 && i <= maxNum && !seenIndices[i-1] {
							indices = append(indices, i-1)
							seenIndices[i-1] = true
						}
					}
				}
			}
		} else {
			// 处理单个数字
			num, err := strconv.Atoi(part)
			if err == nil && num >= 1 && num <= maxNum && !seenIndices[num-1] {
				indices = append(indices, num-1)
				seenIndices[num-1] = true
			}
		}
	}

	return indices
}

// ===== 初始化和配置加载 =====

func loadOrCreateConfig() error {
	ex, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(ex)
	configFilePath = filepath.Join(dir, "config.json")
	indexHTMLPath = filepath.Join(dir, "index.html")

	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("非交互模式下需要配置文件")
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Println("🎯 首次配置向导")
		fmt.Println("================")

		port := readInput(reader, "代理端口", "1080")
		webPort := readInput(reader, "Web管理端口", "8080")
		webUser := readInput(reader, "Web管理员账号", "admin")
		webPass := readInput(reader, "Web管理员密码", "admin123")
		proxyUser := readInput(reader, "代理用户名", "proxy")
		proxyPass := readInput(reader, "代理密码", "proxy123")

		// 自动检测IPv6前缀
		fmt.Println("\n📡 自动检测IPv6前缀...")
		detectedPrefixes := detectIPv6Prefixes()
		
		var prefixes []string
		if len(detectedPrefixes) == 0 {
			fmt.Println("❌ 未检测到任何IPv6前缀")
			fmt.Println("💡 请确保：")
			fmt.Println("   1. 网卡已配置IPv6地址")
			fmt.Println("   2. IPv6地址不是链路本地地址 (fe80::)")
			fmt.Println("   3. 使用 'ip -6 addr' 查看IPv6配置")
			os.Exit(1)
		}
		
		fmt.Printf("\n✅ 检测到 %d 个可用的IPv6前缀:\n\n", len(detectedPrefixes))
		for i, p := range detectedPrefixes {
			fmt.Printf("  [%d] %s (网卡: %s)\n", i+1, p.Prefix, p.Interface)
			fmt.Printf("      示例地址: %s\n", p.SampleIP)
			fmt.Printf("      前缀长度: /%d\n\n", p.PrefixLen)
		}
		
		fmt.Println("请选择要启用的前缀（支持多选）:")
		fmt.Println("  格式1: 单个编号，如 1")
		fmt.Println("  格式2: 逗号分隔，如 1,2,3")
		fmt.Println("  格式3: 空格分隔，如 1 2 3")
		fmt.Println("  格式4: 范围选择，如 1-3")
		fmt.Println("  格式5: 混合使用，如 1 3-5 7")
		fmt.Println("  格式6: 全选，输入 all")
		fmt.Print("\n请输入: ")
		
		selection, _ := reader.ReadString('\n')
		selection = strings.TrimSpace(selection)
		
		selectedIndices := parseSelection(selection, len(detectedPrefixes))
		if len(selectedIndices) == 0 {
			fmt.Println("❌ 未选择任何前缀")
			os.Exit(1)
		}
		
		for _, idx := range selectedIndices {
			prefixes = append(prefixes, detectedPrefixes[idx].Prefix)
			fmt.Printf("✅ 已启用: %s (网卡: %s)\n", 
				detectedPrefixes[idx].Prefix, detectedPrefixes[idx].Interface)
		}
		
		// 询问是否手动添加更多前缀
		fmt.Print("\n是否手动添加其他IPv6前缀? (y/n) [n]: ")
		addMore, _ := reader.ReadString('\n')
		addMore = strings.ToLower(strings.TrimSpace(addMore))
		
		if addMore == "y" || addMore == "yes" {
			fmt.Println("\n📝 手动添加IPv6前缀")
			fmt.Println("格式示例: 2001:db8:1234::/64")
			for {
				fmt.Print("输入前缀 (留空完成): ")
				prefix, _ := reader.ReadString('\n')
				prefix = strings.TrimSpace(prefix)
				
				if prefix == "" {
					break
				}
				
				// 验证前缀格式
				if _, _, err := net.ParseCIDR(prefix); err != nil {
					fmt.Printf("❌ 无效格式: %v\n", err)
					continue
				}
				
				// 检查是否重复
				duplicate := false
				for _, p := range prefixes {
					if p == prefix {
						fmt.Println("⚠️  该前缀已存在")
						duplicate = true
						break
					}
				}
				
				if !duplicate {
					prefixes = append(prefixes, prefix)
					fmt.Printf("✅ 已添加: %s\n", prefix)
				}
			}
		}

		iface := detectedPrefixes[selectedIndices[0]].Interface
		initialPool := readInput(reader, "初始IP池大小", "100")
		targetPool := readInput(reader, "目标IP池大小", "1000")

		initialPoolInt, _ := strconv.Atoi(initialPool)
		targetPoolInt, _ := strconv.Atoi(targetPool)

		config = Config{
			Port:                port,
			WebPort:             webPort,
			WebUsername:         webUser,
			WebPassword:         webPass,
			Username:            proxyUser,
			Password:            proxyPass,
			IPv6Prefixes:        prefixes,
			ActivePrefixIndex:   0,
			AutoSwitchPrefix:    false,
			SwitchIntervalHours: 24,
			Interface:           iface,
			InitialPool:         initialPoolInt,
			TargetPool:          targetPoolInt,
			AutoRotate:          false,
			AutoRotateHours:     24,
			AutoClean:           false,
			Ports:               []PortConfig{},
		}

		fmt.Println("\n" + strings.Repeat("=", 50))
		fmt.Println("📋 配置摘要")
		fmt.Println(strings.Repeat("=", 50))
		fmt.Printf("代理端口: %s\n", port)
		fmt.Printf("Web端口: %s\n", webPort)
		fmt.Printf("网络接口: %s\n", iface)
		fmt.Printf("IPv6前缀数量: %d\n", len(prefixes))
		fmt.Println("\n已配置的IPv6前缀:")
		for i, p := range prefixes {
			if i == 0 {
				fmt.Printf("  [%d] %s ⭐ (默认启用)\n", i+1, p)
			} else {
				fmt.Printf("  [%d] %s\n", i+1, p)
			}
		}
		fmt.Println(strings.Repeat("=", 50) + "\n")

		return saveConfig()
	}

	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	// 向后兼容：如果只有旧的单前缀，迁移到新的多前缀格式
	if len(config.IPv6Prefixes) == 0 && config.IPv6Prefix != "" {
		config.IPv6Prefixes = []string{config.IPv6Prefix}
		config.ActivePrefixIndex = 0
		saveConfig()
	}

	// 确保至少有一个前缀
	if len(config.IPv6Prefixes) == 0 {
		return errors.New("配置中没有IPv6前缀")
	}

	// 确保索引有效
	if config.ActivePrefixIndex < 0 || config.ActivePrefixIndex >= len(config.IPv6Prefixes) {
		config.ActivePrefixIndex = 0
		saveConfig()
	}

	// 初始化自动切换时间
	if config.AutoSwitchPrefix && config.SwitchIntervalHours > 0 {
		nextSwitchTime = time.Now().Add(time.Duration(config.SwitchIntervalHours) * time.Hour)
		atomic.StoreInt32(&autoSwitchEnabled, 1)
	}

	return nil
}

func saveConfig() error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFilePath, data, 0644)
}

func readInput(reader *bufio.Reader, prompt, defaultVal string) string {
	fmt.Printf("%s [%s]: ", prompt, defaultVal)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// ===== 前缀管理功能 =====

// 切换到指定的前缀索引
func switchToPrefix(index int) error {
	poolLock.Lock()
	defer poolLock.Unlock()

	if index < 0 || index >= len(config.IPv6Prefixes) {
		return fmt.Errorf("无效的前缀索引: %d", index)
	}

	if index == config.ActivePrefixIndex {
		return fmt.Errorf("已经在使用前缀 #%d", index)
	}

	oldPrefix := config.IPv6Prefixes[config.ActivePrefixIndex]
	newPrefix := config.IPv6Prefixes[index]

	log.Printf("🔄 开始切换前缀: #%d (%s) -> #%d (%s)", 
		config.ActivePrefixIndex, oldPrefix, index, newPrefix)

	// 清空当前IP池
	ipv6Pool = make([]net.IP, 0, config.TargetPool)
	ipv6PoolIndex = make(map[string]int)

	// 尝试初始化新前缀
	if err := initIPv6WithPrefix(newPrefix); err != nil {
		log.Printf("❌ 切换到前缀 #%d 失败: %v，回退到 #%d", index, err, config.ActivePrefixIndex)
		// 回退到原前缀
		if err2 := initIPv6WithPrefix(oldPrefix); err2 != nil {
			log.Printf("❌ 严重错误：无法回退到原前缀: %v", err2)
			return fmt.Errorf("切换失败且无法回退: %v", err)
		}
		return fmt.Errorf("切换失败: %v", err)
	}

	// 更新配置
	config.ActivePrefixIndex = index
	if err := saveConfig(); err != nil {
		log.Printf("⚠️  切换成功但保存配置失败: %v", err)
	}

	// 重新填充IP池
	go fillInitialPool()

	log.Printf("✅ 成功切换到前缀 #%d: %s", index, newPrefix)
	atomic.StoreInt64(&stats.PoolSize, 0)

	return nil
}

// 自动切换到下一个前缀
func autoSwitchToNextPrefix() error {
	if len(config.IPv6Prefixes) <= 1 {
		return errors.New("只有一个前缀，无法切换")
	}

	nextIndex := (config.ActivePrefixIndex + 1) % len(config.IPv6Prefixes)
	return switchToPrefix(nextIndex)
}

// 添加新前缀
func addPrefix(prefix string) error {
	poolLock.Lock()
	defer poolLock.Unlock()

	// 验证前缀格式
	if _, _, err := net.ParseCIDR(prefix); err != nil {
		return fmt.Errorf("无效的IPv6前缀格式: %v", err)
	}

	// 检查是否已存在
	for _, p := range config.IPv6Prefixes {
		if p == prefix {
			return fmt.Errorf("前缀已存在: %s", prefix)
		}
	}

	config.IPv6Prefixes = append(config.IPv6Prefixes, prefix)
	if err := saveConfig(); err != nil {
		// 回滚
		config.IPv6Prefixes = config.IPv6Prefixes[:len(config.IPv6Prefixes)-1]
		return fmt.Errorf("保存配置失败: %v", err)
	}

	log.Printf("✅ 添加新前缀: %s", prefix)
	return nil
}

// 删除前缀
func deletePrefix(index int) error {
	poolLock.Lock()
	defer poolLock.Unlock()

	if len(config.IPv6Prefixes) <= 1 {
		return errors.New("至少需要保留一个前缀")
	}

	if index < 0 || index >= len(config.IPv6Prefixes) {
		return fmt.Errorf("无效的前缀索引: %d", index)
	}

	if index == config.ActivePrefixIndex {
		return errors.New("不能删除当前使用的前缀，请先切换到其他前缀")
	}

	oldPrefix := config.IPv6Prefixes[index]
	config.IPv6Prefixes = append(config.IPv6Prefixes[:index], config.IPv6Prefixes[index+1:]...)

	// 调整活动前缀索引
	if config.ActivePrefixIndex > index {
		config.ActivePrefixIndex--
	}

	if err := saveConfig(); err != nil {
		return fmt.Errorf("保存配置失败: %v", err)
	}

	log.Printf("✅ 删除前缀: %s", oldPrefix)
	return nil
}

// 获取前缀状态
func getPrefixStatus() PrefixStatus {
	poolLock.RLock()
	defer poolLock.RUnlock()

	prefixes := make([]PrefixInfo, len(config.IPv6Prefixes))
	for i, prefix := range config.IPv6Prefixes {
		info := PrefixInfo{
			Prefix:   prefix,
			Index:    i,
			IsActive: i == config.ActivePrefixIndex,
			IsValid:  true,
		}

		// 验证前缀
		if _, _, err := net.ParseCIDR(prefix); err != nil {
			info.IsValid = false
			info.ErrorMsg = err.Error()
		}

		prefixes[i] = info
	}

	nextSwitchTimeLock.RLock()
	nextSwitch := nextSwitchTime
	nextSwitchTimeLock.RUnlock()

	var nextSwitchStr string
	var secondsUntil int64
	if atomic.LoadInt32(&autoSwitchEnabled) == 1 {
		nextSwitchStr = nextSwitch.Format("2006-01-02 15:04:05")
		secondsUntil = int64(time.Until(nextSwitch).Seconds())
		if secondsUntil < 0 {
			secondsUntil = 0
		}
	}

	return PrefixStatus{
		Prefixes:            prefixes,
		ActiveIndex:         config.ActivePrefixIndex,
		AutoSwitchEnabled:   atomic.LoadInt32(&autoSwitchEnabled) == 1,
		SwitchIntervalHours: config.SwitchIntervalHours,
		NextSwitchTime:      nextSwitchStr,
		SecondsUntilSwitch:  secondsUntil,
	}
}

// 设置自动切换
func setAutoSwitch(enabled bool, intervalHours int) error {
	poolLock.Lock()
	defer poolLock.Unlock()

	config.AutoSwitchPrefix = enabled
	if intervalHours > 0 {
		config.SwitchIntervalHours = intervalHours
	}

	if enabled {
		atomic.StoreInt32(&autoSwitchEnabled, 1)
		nextSwitchTimeLock.Lock()
		nextSwitchTime = time.Now().Add(time.Duration(config.SwitchIntervalHours) * time.Hour)
		nextSwitchTimeLock.Unlock()
		log.Printf("✅ 启用自动切换前缀，间隔: %d小时", config.SwitchIntervalHours)
	} else {
		atomic.StoreInt32(&autoSwitchEnabled, 0)
		log.Printf("✅ 关闭自动切换前缀")
	}

	return saveConfig()
}

// 自动切换监控goroutine
func startAutoSwitchMonitor() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if atomic.LoadInt32(&autoSwitchEnabled) != 1 {
				continue
			}

			nextSwitchTimeLock.RLock()
			shouldSwitch := time.Now().After(nextSwitchTime)
			nextSwitchTimeLock.RUnlock()

			if shouldSwitch {
				log.Printf("⏰ 触发自动切换前缀")
				if err := autoSwitchToNextPrefix(); err != nil {
					log.Printf("❌ 自动切换失败: %v", err)
				} else {
					// 设置下次切换时间
					nextSwitchTimeLock.Lock()
					nextSwitchTime = time.Now().Add(time.Duration(config.SwitchIntervalHours) * time.Hour)
					nextSwitchTimeLock.Unlock()
				}
			}
		}
	}()
}

// ===== IPv6初始化（支持指定前缀） =====

func initIPv6WithPrefix(prefix string) error {
	var err error
	
	// 解析前缀
	prefixIP, prefixNet, err = net.ParseCIDR(prefix)
	if err != nil {
		return fmt.Errorf("无效的IPv6前缀 %s: %v", prefix, err)
	}

	if prefixIP.To4() != nil {
		return fmt.Errorf("不是IPv6地址: %s", prefix)
	}

	prefixIP = prefixIP.To16()

	// 获取网络接口
	iface, err = netlink.LinkByName(config.Interface)
	if err != nil {
		return fmt.Errorf("网络接口 %s 不存在: %v", config.Interface, err)
	}

	ones, _ := prefixNet.Mask.Size()
	if ones > 64 {
		return fmt.Errorf("前缀长度必须 ≤64 (当前: /%d)", ones)
	}

	log.Printf("✅ IPv6前缀初始化成功: %s on %s", prefix, config.Interface)
	return nil
}

func initIPv6() error {
	activePrefix := config.IPv6Prefixes[config.ActivePrefixIndex]
	log.Printf("📡 使用IPv6前缀 #%d: %s", config.ActivePrefixIndex, activePrefix)
	return initIPv6WithPrefix(activePrefix)
}

func generateIPv6() (net.IP, error) {
	poolLock.Lock()
	defer poolLock.Unlock()

	if len(ipv6Pool) == 0 {
		return nil, errors.New("IP池为空")
	}

	rngLock.Lock()
	idx := rng.Intn(len(ipv6Pool))
	rngLock.Unlock()

	ip := ipv6Pool[idx]
	ipv6Pool = append(ipv6Pool[:idx], ipv6Pool[idx+1:]...)
	delete(ipv6PoolIndex, ip.String())
	atomic.AddInt64(&stats.PoolSize, -1)

	return ip, nil
}

func addIPToPool(ip net.IP) bool {
	poolLock.Lock()
	defer poolLock.Unlock()

	if len(ipv6Pool) >= config.TargetPool {
		return false
	}

	key := ip.String()
	if _, exists := ipv6PoolIndex[key]; exists {
		return false
	}

	ipv6Pool = append(ipv6Pool, ip)
	ipv6PoolIndex[key] = len(ipv6Pool) - 1
	atomic.AddInt64(&stats.PoolSize, 1)
	return true
}

func createRandomIPv6() net.IP {
	ip := make(net.IP, 16)
	copy(ip, prefixIP)

	ones, _ := prefixNet.Mask.Size()
	randomBytes := ones / 8

	if ones%8 != 0 {
		randomBytes++
	}

	var randData [8]byte
	rand.Read(randData[:])

	for i := randomBytes; i < 16; i++ {
		ip[i] = randData[i-randomBytes]
	}

	if ones%8 != 0 {
		remainingBits := 8 - (ones % 8)
		mask := byte((1 << remainingBits) - 1)
		ip[randomBytes] = (ip[randomBytes] & ^mask) | (randData[0] & mask)
	}

	return ip
}

func addIPv6ToInterface(ip net.IP) error {
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		},
	}

	if err := netlink.AddrAdd(iface, addr); err != nil {
		if !strings.Contains(err.Error(), "file exists") {
			return err
		}
	}

	return nil
}

func deleteIPv6FromInterface(ip net.IP) {
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(128, 128),
		},
	}
	netlink.AddrDel(iface, addr)
}

func fillInitialPool() {
	log.Printf("🔄 开始填充初始IP池 (%d个)...", config.InitialPool)
	start := time.Now()

	wg := sync.WaitGroup{}
	sem := make(chan struct{}, 50)

	successCount := int64(0)
	for i := 0; i < config.InitialPool; i++ {
		if int(atomic.LoadInt64(&stats.PoolSize)) >= config.InitialPool {
			break
		}

		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			ip := createRandomIPv6()
			if err := addIPv6ToInterface(ip); err == nil {
				if addIPToPool(ip) {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)
	log.Printf("✅ IP池填充完成: %d个, 耗时: %v", successCount, elapsed)
}

func startBackgroundIPManager() {
	if !atomic.CompareAndSwapInt32(&backgroundRunning, 0, 1) {
		return
	}

	discardQueue = make(chan net.IP, 10000)

	go func() {
		for ip := range discardQueue {
			deleteIPv6FromInterface(ip)
		}
	}()

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			currentSize := int(atomic.LoadInt64(&stats.PoolSize))
			if currentSize >= config.TargetPool {
				continue
			}

			batchSize := 10
			if config.TargetPool-currentSize < batchSize {
				batchSize = config.TargetPool - currentSize
			}

			for i := 0; i < batchSize; i++ {
				go func() {
					ip := createRandomIPv6()
					if err := addIPv6ToInterface(ip); err == nil {
						if addIPToPool(ip) {
							atomic.AddInt64(&backgroundAdded, 1)
						}
					}
				}()
			}
		}
	}()
}

// ===== SOCKS5代理核心 =====

func handleClient(clientConn net.Conn, serverIndex int, portCfg *PortConfig) {
	defer clientConn.Close()
	startTime := time.Now()

	atomic.AddInt64(&stats.TotalConns, 1)
	atomic.AddInt64(&stats.ActiveConns, 1)
	defer atomic.AddInt64(&stats.ActiveConns, -1)

	clientIP := clientConn.RemoteAddr().String()

	var authUser, authPass string
	if portCfg != nil {
		authUser = portCfg.Username
		authPass = portCfg.Password
	} else {
		authUser = config.Username
		authPass = config.Password
	}

	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 5 {
		atomic.AddInt64(&stats.FailedConns, 1)
		addFailLog(clientIP, "无效请求", "", "协议错误", time.Since(startTime))
		return
	}

	clientConn.Write([]byte{5, 2})

	n, err = clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 1 {
		atomic.AddInt64(&stats.FailedConns, 1)
		addFailLog(clientIP, "认证失败", "", "无效认证", time.Since(startTime))
		return
	}

	userLen := int(buf[1])
	if n < 2+userLen+1 {
		atomic.AddInt64(&stats.FailedConns, 1)
		addFailLog(clientIP, "认证失败", "", "数据不完整", time.Since(startTime))
		return
	}

	username := string(buf[2 : 2+userLen])
	passLen := int(buf[2+userLen])
	if n < 2+userLen+1+passLen {
		atomic.AddInt64(&stats.FailedConns, 1)
		addFailLog(clientIP, "认证失败", "", "数据不完整", time.Since(startTime))
		return
	}

	password := string(buf[2+userLen+1 : 2+userLen+1+passLen])

	if subtle.ConstantTimeCompare([]byte(username), []byte(authUser)) != 1 ||
		subtle.ConstantTimeCompare([]byte(password), []byte(authPass)) != 1 {
		clientConn.Write([]byte{1, 1})
		atomic.AddInt64(&stats.FailedConns, 1)
		addFailLog(clientIP, "认证失败", "", "用户名或密码错误", time.Since(startTime))
		return
	}

	clientConn.Write([]byte{1, 0})

	n, err = clientConn.Read(buf)
	if err != nil || n < 4 || buf[0] != 5 || buf[1] != 1 {
		atomic.AddInt64(&stats.FailedConns, 1)
		addFailLog(clientIP, "连接失败", "", "无效请求", time.Since(startTime))
		return
	}

	var targetAddr string
	switch buf[3] {
	case 1:
		if n < 10 {
			atomic.AddInt64(&stats.FailedConns, 1)
			addFailLog(clientIP, "连接失败", "", "IPv4地址不完整", time.Since(startTime))
			return
		}
		ip := net.IP(buf[4:8])
		port := binary.BigEndian.Uint16(buf[8:10])
		targetAddr = fmt.Sprintf("%s:%d", ip, port)
	case 3:
		if n < 5 {
			atomic.AddInt64(&stats.FailedConns, 1)
			addFailLog(clientIP, "连接失败", "", "域名数据不完整", time.Since(startTime))
			return
		}
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			atomic.AddInt64(&stats.FailedConns, 1)
			addFailLog(clientIP, "连接失败", "", "域名数据不完整", time.Since(startTime))
			return
		}
		domain := string(buf[5 : 5+domainLen])
		port := binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
	case 4:
		if n < 22 {
			atomic.AddInt64(&stats.FailedConns, 1)
			addFailLog(clientIP, "连接失败", "", "IPv6地址不完整", time.Since(startTime))
			return
		}
		ip := net.IP(buf[4:20])
		port := binary.BigEndian.Uint16(buf[20:22])
		targetAddr = fmt.Sprintf("[%s]:%d", ip, port)
	default:
		clientConn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&stats.FailedConns, 1)
		addFailLog(clientIP, targetAddr, "", "不支持的地址类型", time.Since(startTime))
		return
	}

	srcIP, err := generateIPv6()
	if err != nil {
		clientConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&stats.FailedConns, 1)
		addFailLog(clientIP, targetAddr, "", "IP池耗尽", time.Since(startTime))
		return
	}

	srcAddr := &net.TCPAddr{IP: srcIP, Port: 0}
	dialer := &net.Dialer{
		LocalAddr: srcAddr,
		Timeout:   10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	connID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), clientIP)
	addActiveConn(connID, clientIP, targetAddr, srcIP.String())

	remoteConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		clientConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&stats.FailedConns, 1)
		addFailLog(clientIP, targetAddr, srcIP.String(), fmt.Sprintf("连接失败: %v", err), time.Since(startTime))
		
		discardQueue <- srcIP
		removeActiveConn(connID)
		return
	}
	defer remoteConn.Close()

	clientConn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	atomic.AddInt64(&stats.SuccessConns, 1)
	addConnLog(clientIP, targetAddr, srcIP.String(), "成功", time.Since(startTime))

	var wg sync.WaitGroup
	wg.Add(2)

	var clientToRemote, remoteToClient int64

	go func() {
		defer wg.Done()
		n, _ := io.Copy(remoteConn, clientConn)
		atomic.AddInt64(&clientToRemote, n)
		remoteConn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, remoteConn)
		atomic.AddInt64(&remoteToClient, n)
		clientConn.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()

	atomic.AddInt64(&stats.TotalBytesSent, clientToRemote)
	atomic.AddInt64(&stats.TotalBytesRecv, remoteToClient)

	duration := time.Since(startTime)
	atomic.AddInt64(&stats.TotalDuration, int64(duration))

	discardQueue <- srcIP
	removeActiveConn(connID)
}

func addConnLog(clientIP, target, ipv6, status string, duration time.Duration) {
	connLogsLock.Lock()
	defer connLogsLock.Unlock()

	log := &ConnLog{
		Time:     time.Now().Format("15:04:05"),
		ClientIP: clientIP,
		Target:   target,
		IPv6:     ipv6,
		Status:   status,
		Duration: duration.Round(time.Millisecond).String(),
	}

	connLogs = append([]*ConnLog{log}, connLogs...)
	if len(connLogs) > maxLogs {
		connLogs = connLogs[:maxLogs]
	}
}

func addFailLog(clientIP, target, ipv6, status string, duration time.Duration) {
	failLogsLock.Lock()
	defer failLogsLock.Unlock()

	log := &ConnLog{
		Time:     time.Now().Format("15:04:05"),
		ClientIP: clientIP,
		Target:   target,
		IPv6:     ipv6,
		Status:   status,
		Duration: duration.Round(time.Millisecond).String(),
	}

	failLogs = append([]*ConnLog{log}, failLogs...)
	if len(failLogs) > maxLogs {
		failLogs = failLogs[:maxLogs]
	}
}

func addActiveConn(id, clientIP, target, ipv6 string) {
	activeConnectionsLock.Lock()
	defer activeConnectionsLock.Unlock()

	activeConnections[id] = &ActiveConn{
		ID:        id,
		ClientIP:  clientIP,
		Target:    target,
		IPv6:      ipv6,
		StartTime: time.Now(),
		Duration:  "0s",
	}
}

func removeActiveConn(id string) {
	activeConnectionsLock.Lock()
	defer activeConnectionsLock.Unlock()
	delete(activeConnections, id)
}

func updateActiveConnDurations() {
	activeConnectionsLock.Lock()
	defer activeConnectionsLock.Unlock()

	for _, conn := range activeConnections {
		conn.Duration = time.Since(conn.StartTime).Round(time.Second).String()
	}
}

// ===== HTTP API =====

func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	uptime := time.Since(stats.StartTime)
	avgDuration := int64(0)
	if stats.SuccessConns > 0 {
		avgDuration = stats.TotalDuration / stats.SuccessConns
	}

	successRate := float64(0)
	if stats.TotalConns > 0 {
		successRate = float64(stats.SuccessConns) / float64(stats.TotalConns) * 100
	}

	qps := float64(0)
	if uptime.Seconds() > 0 {
		qps = float64(stats.SuccessConns) / uptime.Seconds()
	}

	currentPrefix := ""
	if config.ActivePrefixIndex >= 0 && config.ActivePrefixIndex < len(config.IPv6Prefixes) {
		currentPrefix = config.IPv6Prefixes[config.ActivePrefixIndex]
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_conns":       atomic.LoadInt64(&stats.TotalConns),
		"active_conns":      atomic.LoadInt64(&stats.ActiveConns),
		"success_conns":     atomic.LoadInt64(&stats.SuccessConns),
		"failed_conns":      atomic.LoadInt64(&stats.FailedConns),
		"timeout_conns":     atomic.LoadInt64(&stats.TimeoutConns),
		"pool_size":         atomic.LoadInt64(&stats.PoolSize),
		"target_pool":       config.TargetPool,
		"uptime":            int64(uptime.Seconds()),
		"uptime_str":        uptime.Round(time.Second).String(),
		"avg_duration_ms":   avgDuration / 1e6,
		"success_rate":      fmt.Sprintf("%.2f%%", successRate),
		"qps":               fmt.Sprintf("%.2f", qps),
		"process_cpu":       float64(atomic.LoadInt64(&stats.ProcessCPUPercent)) / 100,
		"system_cpu":        float64(atomic.LoadInt64(&stats.SystemCPUPercent)) / 100,
		"total_recv_mb":     float64(atomic.LoadInt64(&stats.TotalBytesRecv)) / 1024 / 1024,
		"total_sent_mb":     float64(atomic.LoadInt64(&stats.TotalBytesSent)) / 1024 / 1024,
		"recv_rate_mbps":    float64(atomic.LoadInt64(&stats.CurrentRecvRate)) * 8 / 1024 / 1024,
		"send_rate_mbps":    float64(atomic.LoadInt64(&stats.CurrentSendRate)) * 8 / 1024 / 1024,
		"current_prefix":    currentPrefix,
		"prefix_index":      config.ActivePrefixIndex,
		"total_prefixes":    len(config.IPv6Prefixes),
	})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	connLogsLock.RLock()
	defer connLogsLock.RUnlock()
	json.NewEncoder(w).Encode(connLogs)
}

func handleFailLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	failLogsLock.RLock()
	defer failLogsLock.RUnlock()
	json.NewEncoder(w).Encode(failLogs)
}

func handleActiveConns(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	updateActiveConnDurations()

	activeConnectionsLock.RLock()
	defer activeConnectionsLock.RUnlock()

	conns := make([]*ActiveConn, 0, len(activeConnections))
	for _, conn := range activeConnections {
		conns = append(conns, conn)
	}

	json.NewEncoder(w).Encode(conns)
}

func handleChart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	statsHistoryLock.RLock()
	defer statsHistoryLock.RUnlock()
	json.NewEncoder(w).Encode(statsHistory)
}

func handleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	poolLock.Lock()
	defer poolLock.Unlock()

	oldSize := len(ipv6Pool)
	
	for _, ip := range ipv6Pool {
		discardQueue <- ip
	}

	ipv6Pool = make([]net.IP, 0, config.TargetPool)
	ipv6PoolIndex = make(map[string]int)
	atomic.StoreInt64(&stats.PoolSize, 0)

	go fillInitialPool()

	log.Printf("🔄 手动轮换: 丢弃 %d 个IP", oldSize)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"message":      "IP池已轮换",
		"discarded":    oldSize,
		"next_rotate":  nextRotateTime.Format("2006-01-02 15:04:05"),
	})
}

func handleAutoRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
		Hours   int  `json:"hours"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	config.AutoRotate = req.Enabled
	if req.Hours > 0 {
		config.AutoRotateHours = req.Hours
	}

	if config.AutoRotate {
		atomic.StoreInt32(&autoRotateEnabled, 1)
		nextRotateTimeLock.Lock()
		nextRotateTime = time.Now().Add(time.Duration(config.AutoRotateHours) * time.Hour)
		nextRotateTimeLock.Unlock()
	} else {
		atomic.StoreInt32(&autoRotateEnabled, 0)
	}

	if err := saveConfig(); err != nil {
		http.Error(w, "保存配置失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"enabled":     config.AutoRotate,
		"hours":       config.AutoRotateHours,
		"next_rotate": nextRotateTime.Format("2006-01-02 15:04:05"),
	})
}

func handlePorts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config.Ports)
}

func handleAddPort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Port     string `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, p := range config.Ports {
		if p.Port == req.Port {
			http.Error(w, "端口已存在", http.StatusBadRequest)
			return
		}
	}

	config.Ports = append(config.Ports, PortConfig{
		Port:     req.Port,
		Username: req.Username,
		Password: req.Password,
	})

	if err := saveConfig(); err != nil {
		http.Error(w, "保存失败", http.StatusInternalServerError)
		return
	}

	portNum, _ := strconv.Atoi(req.Port)
	go startProxyServer(portNum, len(config.Ports)-1, &config.Ports[len(config.Ports)-1])

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("端口 %s 添加成功", req.Port),
	})
}

func handleBatchAddPorts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		StartPort int    `json:"start_port"`
		EndPort   int    `json:"end_port"`
		Username  string `json:"username"`
		Password  string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.EndPort-req.StartPort > 100 {
		http.Error(w, "一次最多添加100个端口", http.StatusBadRequest)
		return
	}

	added := 0
	for port := req.StartPort; port <= req.EndPort; port++ {
		portStr := strconv.Itoa(port)
		
		exists := false
		for _, p := range config.Ports {
			if p.Port == portStr {
				exists = true
				break
			}
		}
		
		if exists {
			continue
		}

		config.Ports = append(config.Ports, PortConfig{
			Port:     portStr,
			Username: req.Username,
			Password: req.Password,
		})

		go startProxyServer(port, len(config.Ports)-1, &config.Ports[len(config.Ports)-1])
		added++
	}

	if err := saveConfig(); err != nil {
		http.Error(w, "保存失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("成功添加 %d 个端口", added),
	})
}

func handleDeletePort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Port string `json:"port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	found := false
	for i, p := range config.Ports {
		if p.Port == req.Port {
			config.Ports = append(config.Ports[:i], config.Ports[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "端口不存在", http.StatusNotFound)
		return
	}

	if err := saveConfig(); err != nil {
		http.Error(w, "保存失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("端口 %s 已删除（需重启生效）", req.Port),
	})
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Port     string `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	found := false
	for i := range config.Ports {
		if config.Ports[i].Port == req.Port {
			config.Ports[i].Username = req.Username
			config.Ports[i].Password = req.Password
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "端口不存在", http.StatusNotFound)
		return
	}

	if err := saveConfig(); err != nil {
		http.Error(w, "保存失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "密码已更新",
	})
}

// ===== 多前缀API处理函数 =====

func handlePrefixes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := getPrefixStatus()
	json.NewEncoder(w).Encode(status)
}

func handleDetectPrefixes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	detected := detectIPv6Prefixes()
	
	// 过滤掉已配置的前缀
	var available []DetectedPrefix
	for _, d := range detected {
		found := false
		for _, configured := range config.IPv6Prefixes {
			if d.Prefix == configured {
				found = true
				break
			}
		}
		if !found {
			available = append(available, d)
		}
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"detected": detected,
		"available": available,
	})
}

func handleSwitchPrefix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Index int `json:"index"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := switchToPrefix(req.Index); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("已切换到前缀 #%d", req.Index),
		"prefix":  config.IPv6Prefixes[req.Index],
	})
}

func handleAddPrefix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Prefix string `json:"prefix"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := addPrefix(req.Prefix); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "前缀添加成功",
		"prefix":  req.Prefix,
		"index":   len(config.IPv6Prefixes) - 1,
	})
}

func handleDeletePrefix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Index int `json:"index"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := deletePrefix(req.Index); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("前缀 #%d 已删除", req.Index),
	})
}

func handleAutoSwitchPrefix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
		Hours   int  `json:"hours"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := setAutoSwitch(req.Enabled, req.Hours); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	nextSwitchTimeLock.RLock()
	nextSwitch := nextSwitchTime
	nextSwitchTimeLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"enabled":     req.Enabled,
		"hours":       config.SwitchIntervalHours,
		"next_switch": nextSwitch.Format("2006-01-02 15:04:05"),
	})
}

// ===== Web服务器和认证 =====

func basicAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(config.WebUsername)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(config.WebPassword)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func startWebServer() {
	http.HandleFunc("/", basicAuth(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, indexHTMLPath)
	}))

	http.HandleFunc("/api/stats", basicAuth(handleStats))
	http.HandleFunc("/api/logs", basicAuth(handleLogs))
	http.HandleFunc("/api/faillogs", basicAuth(handleFailLogs))
	http.HandleFunc("/api/active", basicAuth(handleActiveConns))
	http.HandleFunc("/api/chart", basicAuth(handleChart))
	http.HandleFunc("/api/rotate", basicAuth(handleRotate))
	http.HandleFunc("/api/autorotate", basicAuth(handleAutoRotate))
	http.HandleFunc("/api/ports", basicAuth(handlePorts))
	http.HandleFunc("/api/ports/add", basicAuth(handleAddPort))
	http.HandleFunc("/api/ports/batch", basicAuth(handleBatchAddPorts))
	http.HandleFunc("/api/ports/delete", basicAuth(handleDeletePort))
	http.HandleFunc("/api/changepassword", basicAuth(handleChangePassword))

	// 多前缀API
	http.HandleFunc("/api/prefixes", basicAuth(handlePrefixes))
	http.HandleFunc("/api/prefixes/detect", basicAuth(handleDetectPrefixes))
	http.HandleFunc("/api/prefixes/switch", basicAuth(handleSwitchPrefix))
	http.HandleFunc("/api/prefixes/add", basicAuth(handleAddPrefix))
	http.HandleFunc("/api/prefixes/delete", basicAuth(handleDeletePrefix))
	http.HandleFunc("/api/prefixes/auto-switch", basicAuth(handleAutoSwitchPrefix))

	log.Printf("🌐 Web管理: http://0.0.0.0:%s", config.WebPort)
	log.Fatal(http.ListenAndServe(":"+config.WebPort, nil))
}

func startProxyServer(port, index int, portCfg *PortConfig) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("❌ 无法启动端口 %d: %v", port, err)
		return
	}
	defer listener.Close()

	log.Printf("🚀 代理端口 %d 已启动", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(conn, index, portCfg)
	}
}

func startCPUMonitor() {
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		pid := int32(os.Getpid())
		proc, _ := process.NewProcess(pid)

		for range ticker.C {
			if percent, err := proc.CPUPercent(); err == nil {
				atomic.StoreInt64(&stats.ProcessCPUPercent, int64(percent*100))
			}

			if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
				atomic.StoreInt64(&stats.SystemCPUPercent, int64(percents[0]*100))
			}
		}
	}()
}

func startStatsRecorder() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		lastSuccess := int64(0)
		lastTime := time.Now()

		for range ticker.C {
			currentTotal := atomic.LoadInt64(&stats.TotalConns)
			currentSuccess := atomic.LoadInt64(&stats.SuccessConns)
			currentTime := time.Now()

			elapsed := currentTime.Sub(lastTime).Seconds()
			qps := float64(currentSuccess-lastSuccess) / elapsed

			successRate := float64(0)
			if currentTotal > 0 {
				successRate = float64(currentSuccess) / float64(currentTotal) * 100
			}

			snapshot := &StatsSnapshot{
				Timestamp:   currentTime.Format("15:04:05"),
				QPS:         qps,
				SuccessRate: successRate,
				ProcessCPU:  float64(atomic.LoadInt64(&stats.ProcessCPUPercent)) / 100,
				SystemCPU:   float64(atomic.LoadInt64(&stats.SystemCPUPercent)) / 100,
				ActiveConns: atomic.LoadInt64(&stats.ActiveConns),
			}

			statsHistoryLock.Lock()
			statsHistory = append(statsHistory, snapshot)
			if len(statsHistory) > maxHistory {
				statsHistory = statsHistory[1:]
			}
			statsHistoryLock.Unlock()

			lastSuccess = currentSuccess
			lastTime = currentTime
		}
	}()
}

func startAutoRotateMonitor() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if atomic.LoadInt32(&autoRotateEnabled) != 1 {
				continue
			}

			nextRotateTimeLock.RLock()
			shouldRotate := time.Now().After(nextRotateTime)
			nextRotateTimeLock.RUnlock()

			if shouldRotate {
				log.Printf("⏰ 触发自动轮换")
				
				poolLock.Lock()
				oldSize := len(ipv6Pool)
				
				for _, ip := range ipv6Pool {
					discardQueue <- ip
				}

				ipv6Pool = make([]net.IP, 0, config.TargetPool)
				ipv6PoolIndex = make(map[string]int)
				atomic.StoreInt64(&stats.PoolSize, 0)
				poolLock.Unlock()

				go fillInitialPool()

				nextRotateTimeLock.Lock()
				nextRotateTime = time.Now().Add(time.Duration(config.AutoRotateHours) * time.Hour)
				nextRotateTimeLock.Unlock()

				log.Printf("✅ 自动轮换完成: 丢弃 %d 个IP", oldSize)
			}
		}
	}()
}

// ===== 主函数 =====

func main() {
	if err := loadOrCreateConfig(); err != nil {
		log.Fatalf("❌ 配置错误: %v", err)
	}

	if len(config.IPv6Prefixes) == 0 {
		log.Fatal("❌ 没有配置IPv6前缀")
	}

	log.Printf("📋 配置的IPv6前缀:")
	for i, prefix := range config.IPv6Prefixes {
		if i == config.ActivePrefixIndex {
			log.Printf("   #%d: %s ⭐ (当前激活)", i, prefix)
		} else {
			log.Printf("   #%d: %s", i, prefix)
		}
	}

	if err := initIPv6(); err != nil {
		log.Fatalf("❌ IPv6初始化失败: %v", err)
	}

	stats.StartTime = time.Now()
	ipv6Pool = make([]net.IP, 0, config.TargetPool)
	ipv6PoolIndex = make(map[string]int)

	fillInitialPool()
	startBackgroundIPManager()
	startCPUMonitor()
	startStatsRecorder()
	startAutoRotateMonitor()
	startAutoSwitchMonitor()

	if config.AutoRotate {
		atomic.StoreInt32(&autoRotateEnabled, 1)
		nextRotateTime = time.Now().Add(time.Duration(config.AutoRotateHours) * time.Hour)
		log.Printf("⏰ 自动轮换: 已启用, 间隔 %d 小时", config.AutoRotateHours)
	}

	if config.AutoSwitchPrefix {
		atomic.StoreInt32(&autoSwitchEnabled, 1)
		nextSwitchTime = time.Now().Add(time.Duration(config.SwitchIntervalHours) * time.Hour)
		log.Printf("⏰ 自动切换前缀: 已启用, 间隔 %d 小时", config.SwitchIntervalHours)
	}

	go startWebServer()

	basePort, _ := strconv.Atoi(config.Port)
	go startProxyServer(basePort, -1, nil)

	for i := range config.Ports {
		port, _ := strconv.Atoi(config.Ports[i].Port)
		go startProxyServer(port, i, &config.Ports[i])
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\n👋 正在关闭...")
}
GOEOF

print_success "Go代码生成完成"
echo ""

# --- 步骤 4: 创建HTML前端 (包含多前缀管理界面) ---
echo "--- 步骤 4: 创建前端 ---"

cat << 'HTMLEOF' > index.html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPv6 代理运行监控</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Microsoft YaHei', sans-serif;
    background: #0f1419;
    color: #e5e7eb;
    min-height: 100vh;
    padding: 15px;
}

.container {
    max-width: 1600px;
    margin: 0 auto;
}

/* 顶部标题 */
.header {
    background: linear-gradient(135deg, #1e2533 0%, #252d3d 100%);
    padding: 15px 25px;
    border-radius: 8px;
    border: 1px solid #2d3748;
    margin-bottom: 15px;
    display: flex;
    align-items: center;
}

.header-icon {
    font-size: 24px;
    margin-right: 12px;
}

.header h1 {
    font-size: 20px;
    font-weight: 500;
    color: #f0f0f0;
}

/* 统计卡片网格 */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
    margin-bottom: 12px;
}

.stat-card {
    background: linear-gradient(135deg, #1e2533 0%, #252d3d 100%);
    padding: 16px;
    border-radius: 8px;
    border: 1px solid #2d3748;
    transition: all 0.3s;
}

.stat-card:hover {
    border-color: #3b82f6;
    transform: translateY(-2px);
}

.stat-card .label {
    font-size: 12px;
    color: #9ca3af;
    margin-bottom: 8px;
}

.stat-card .value {
    font-size: 28px;
    font-weight: 600;
    color: #3b82f6;
    line-height: 1.2;
}

.stat-card .sub-value {
    font-size: 12px;
    color: #6b7280;
    margin-top: 4px;
}

.stat-card .progress-bar {
    width: 100%;
    height: 3px;
    background: #2d3748;
    border-radius: 2px;
    margin-top: 8px;
    overflow: hidden;
}

.stat-card .progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #3b82f6, #2563eb);
    transition: width 0.3s;
}

/* 功能区网格 */
.function-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 12px;
    margin-bottom: 15px;
}

.function-card {
    background: linear-gradient(135deg, #1e2533 0%, #252d3d 100%);
    padding: 16px;
    border-radius: 8px;
    border: 1px solid #2d3748;
}

.function-card h3 {
    font-size: 14px;
    color: #f0f0f0;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
}

.function-card h3::before {
    content: '⚙️';
    margin-right: 8px;
}

.form-group {
    margin-bottom: 15px;
}

.form-group label {
    display: block;
    font-size: 12px;
    color: #9ca3af;
    margin-bottom: 8px;
}

.form-group input,
.form-group select {
    width: 100%;
    padding: 10px 12px;
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 6px;
    color: #e5e7eb;
    font-size: 14px;
    transition: all 0.3s;
}

.form-group input:focus,
.form-group select:focus {
    outline: none;
    border-color: #3b82f6;
    background: #252d3d;
}

.button {
    width: 100%;
    padding: 10px 16px;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.3s;
    margin-bottom: 8px;
}

.button-primary {
    background: linear-gradient(135deg, #3b82f6, #2563eb);
    color: white;
}

.button-primary:hover {
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
}

.button-warning {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    color: white;
}

.button-warning:hover {
    background: linear-gradient(135deg, #d97706, #b45309);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(245, 158, 11, 0.4);
}

.button-secondary {
    background: #2d3748;
    color: #e5e7eb;
}

.button-secondary:hover {
    background: #374151;
}

/* 图表区域 */
.chart-container {
    background: linear-gradient(135deg, #1e2533 0%, #252d3d 100%);
    padding: 12px 20px 15px;
    border-radius: 8px;
    border: 1px solid #2d3748;
    margin-bottom: 15px;
}

.chart-container h3 {
    font-size: 14px;
    color: #f0f0f0;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
}

.chart-container h3::before {
    content: '📊';
    margin-right: 8px;
}

#chart {
    width: 100%;
    height: 140px;
}

/* 表格 */
.table-container {
    background: linear-gradient(135deg, #1e2533 0%, #252d3d 100%);
    border-radius: 8px;
    border: 1px solid #2d3748;
    margin-bottom: 15px;
    overflow: hidden;
}

.table-header {
    padding: 12px 20px;
    border-bottom: 1px solid #2d3748;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.table-header h3 {
    font-size: 14px;
    color: #f0f0f0;
    display: flex;
    align-items: center;
}

.table-header h3::before {
    content: '🔗';
    margin-right: 8px;
}

.table-badge {
    background: #3b82f6;
    color: white;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 12px;
    margin-left: 8px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

thead {
    background: #1a1f2e;
}

th {
    padding: 10px 16px;
    text-align: left;
    font-size: 12px;
    font-weight: 500;
    color: #9ca3af;
    border-bottom: 1px solid #2d3748;
}

td {
    padding: 10px 16px;
    font-size: 13px;
    color: #e5e7eb;
    border-bottom: 1px solid #2d3748;
}

tr:hover {
    background: #1a1f2e;
}

.status-success {
    color: #10b981;
    font-weight: 500;
}

.status-fail {
    color: #ef4444;
    font-weight: 500;
}

/* 搜索框 */
.search-container {
    background: linear-gradient(135deg, #1e2533 0%, #252d3d 100%);
    padding: 15px 20px;
    border-radius: 8px;
    border: 1px solid #2d3748;
    margin-bottom: 15px;
}

.search-container h3 {
    font-size: 14px;
    color: #f0f0f0;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
}

.search-container h3::before {
    content: '🔍';
    margin-right: 8px;
}

.search-box {
    display: flex;
    gap: 10px;
}

.search-box input {
    flex: 1;
    padding: 10px 12px;
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 6px;
    color: #e5e7eb;
    font-size: 14px;
}

.search-box input:focus {
    outline: none;
    border-color: #3b82f6;
}

.search-box button {
    padding: 10px 20px;
    background: linear-gradient(135deg, #3b82f6, #2563eb);
    border: none;
    border-radius: 6px;
    color: white;
    font-size: 14px;
    cursor: pointer;
    transition: all 0.3s;
}

.search-box button:hover {
    background: linear-gradient(135deg, #2563eb, #1d4ed8);
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
}

/* 前缀管理 */
.prefix-container {
    background: linear-gradient(135deg, #1e2533 0%, #252d3d 100%);
    padding: 15px 20px;
    border-radius: 8px;
    border: 1px solid #2d3748;
    margin-bottom: 15px;
}

.prefix-container h3 {
    font-size: 14px;
    color: #f0f0f0;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
}

.prefix-container h3::before {
    content: '📡';
    margin-right: 8px;
}

.prefix-info {
    background: #1a1f2e;
    padding: 12px 16px;
    border-radius: 6px;
    margin-bottom: 15px;
    font-size: 13px;
}

.prefix-info strong {
    color: #3b82f6;
}

.prefix-list {
    display: grid;
    gap: 10px;
}

.prefix-item {
    background: #1a1f2e;
    padding: 15px;
    border-radius: 6px;
    border: 1px solid #2d3748;
    display: flex;
    justify-content: space-between;
    align-items: center;
    transition: all 0.3s;
}

.prefix-item:hover {
    border-color: #3b82f6;
}

.prefix-item.active {
    background: linear-gradient(135deg, #1e3a8a, #1e40af);
    border-color: #3b82f6;
}

.prefix-item.active .prefix-title {
    color: #60a5fa;
}

.prefix-title {
    font-size: 13px;
    color: #e5e7eb;
    font-weight: 500;
}

.prefix-meta {
    font-size: 11px;
    color: #9ca3af;
    margin-top: 4px;
}

.prefix-badge {
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 500;
    margin-right: 8px;
}

.badge-active {
    background: #10b981;
    color: white;
}

.prefix-actions {
    display: flex;
    gap: 8px;
}

.btn-sm {
    padding: 6px 12px;
    font-size: 12px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.3s;
}

.btn-sm.btn-switch {
    background: #3b82f6;
    color: white;
}

.btn-sm.btn-switch:hover {
    background: #2563eb;
}

.btn-sm.btn-delete {
    background: #ef4444;
    color: white;
}

.btn-sm.btn-delete:hover {
    background: #dc2626;
}

.btn-sm:disabled {
    background: #374151;
    color: #6b7280;
    cursor: not-allowed;
}

/* 自动切换面板 */
.auto-switch-panel {
    background: #1a1f2e;
    padding: 15px;
    border-radius: 6px;
    margin: 15px 0;
}

.switch-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
}

.switch-row label {
    font-size: 13px;
    color: #9ca3af;
}

.switch-toggle {
    position: relative;
    width: 48px;
    height: 24px;
}

.switch-toggle input {
    opacity: 0;
    width: 0;
    height: 0;
}

.slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: #374151;
    transition: .3s;
    border-radius: 24px;
}

.slider:before {
    position: absolute;
    content: "";
    height: 18px;
    width: 18px;
    left: 3px;
    bottom: 3px;
    background-color: white;
    transition: .3s;
    border-radius: 50%;
}

input:checked + .slider {
    background-color: #10b981;
}

input:checked + .slider:before {
    transform: translateX(24px);
}

.countdown {
    background: linear-gradient(135deg, #f59e0b, #d97706);
    padding: 12px;
    border-radius: 6px;
    text-align: center;
    font-size: 13px;
    color: white;
    margin: 15px 0;
}

/* 弹窗 */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.7);
    backdrop-filter: blur(4px);
}

.modal-content {
    background: linear-gradient(135deg, #1e2533 0%, #252d3d 100%);
    margin: 5% auto;
    padding: 30px;
    border: 1px solid #2d3748;
    border-radius: 12px;
    width: 90%;
    max-width: 600px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-content h2 {
    color: #f0f0f0;
    margin-bottom: 20px;
    font-size: 18px;
}

.close {
    color: #9ca3af;
    float: right;
    font-size: 28px;
    font-weight: bold;
    cursor: pointer;
    transition: all 0.3s;
}

.close:hover {
    color: #3b82f6;
}

/* 响应式 */
@media (max-width: 768px) {
    .stats-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .function-grid {
        grid-template-columns: 1fr;
    }
    
    .stat-card .value {
        font-size: 20px;
    }
}

/* 滚动条 */
::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

::-webkit-scrollbar-track {
    background: #1a1f2e;
}

::-webkit-scrollbar-thumb {
    background: #374151;
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: #4b5563;
}

/* 加载动画 */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.loading {
    animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

/* 提示信息 */
.info-text {
    font-size: 12px;
    color: #6b7280;
    margin-top: 8px;
}

.detected-list {
    max-height: 400px;
    overflow-y: auto;
    margin-top: 15px;
}

.detected-item {
    background: #1a1f2e;
    padding: 15px;
    border-radius: 6px;
    margin-bottom: 10px;
    border: 1px solid #2d3748;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.detected-info {
    flex: 1;
}

.detected-info strong {
    color: #3b82f6;
    font-size: 14px;
}

.detected-info small {
    display: block;
    color: #9ca3af;
    font-size: 11px;
    margin-top: 4px;
}
</style>
</head>
<body>

<div class="container">
    <!-- 顶部标题 -->
    <div class="header">
        <span class="header-icon">📡</span>
        <h1>IPv6 代理运行监控 v8.1.1</h1>
    </div>

    <!-- 统计卡片 -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="label">总连接数</div>
            <div class="value" id="total-conns">0</div>
        </div>
        <div class="stat-card">
            <div class="label">成功连接</div>
            <div class="value" id="success-conns">0</div>
            <div class="sub-value">QPS: <span id="qps">0.00</span></div>
        </div>
        <div class="stat-card">
            <div class="label">连接结果</div>
            <div class="value"><span id="success-count">0</span>/<span id="fail-count" style="color:#ef4444">0</span></div>
            <div class="sub-value">成功/失败</div>
        </div>
        <div class="stat-card">
            <div class="label">进程 CPU</div>
            <div class="value" id="process-cpu">0.0 %</div>
            <div class="sub-value">当前进程</div>
        </div>
        <div class="stat-card">
            <div class="label">系统 CPU</div>
            <div class="value" id="system-cpu">0.0 %</div>
            <div class="sub-value">整体系统</div>
        </div>
        <div class="stat-card">
            <div class="label">平均耗时</div>
            <div class="value" id="avg-duration">0 ms</div>
        </div>
        <div class="stat-card">
            <div class="label">IPv6 池</div>
            <div class="value" id="pool-size">0</div>
            <div class="sub-value">当前/目标: <span id="pool-target">0</span></div>
            <div class="progress-bar">
                <div class="progress-fill" id="pool-progress" style="width: 0%"></div>
            </div>
        </div>
    </div>

    <!-- 第二行统计 -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="label">运行时间</div>
            <div class="value" id="uptime" style="font-size: 20px;">0d 0h 0m</div>
        </div>
        <div class="stat-card">
            <div class="label">实时流量</div>
            <div class="value" style="font-size: 18px;">
                <span id="recv-rate">0.00</span> KB/s
            </div>
            <div class="sub-value">↓ 下载 | ↑ 上传 <span id="send-rate">0.00</span> KB/s</div>
        </div>
        <div class="stat-card">
            <div class="label">流量统计</div>
            <div class="value" style="font-size: 18px;">
                <span id="total-recv">0.00</span> GB
            </div>
            <div class="sub-value">↓ 下行 | ↑ 上行 <span id="total-sent">0.00</span> GB</div>
        </div>
    </div>

    <!-- IPv6前缀管理 -->
    <div class="prefix-container">
        <h3>IPv6 前缀管理</h3>
        
        <div class="prefix-info">
            <strong>当前使用:</strong> <span id="current-prefix">加载中...</span> | 
            <strong>前缀数:</strong> <span id="total-prefixes">0</span>
        </div>

        <div class="auto-switch-panel">
            <div class="switch-row">
                <label>⏰ 自动切换前缀</label>
                <label class="switch-toggle">
                    <input type="checkbox" id="auto-switch-enabled" onchange="toggleAutoSwitch()">
                    <span class="slider"></span>
                </label>
            </div>
            <div class="switch-row">
                <label>切换间隔</label>
                <div style="display:flex; gap:10px; align-items:center;">
                    <input type="number" id="switch-interval" min="1" max="168" value="24" 
                           style="width:80px; padding:6px 10px;">
                    <span style="font-size:13px; color:#9ca3af;">小时</span>
                    <button class="btn-sm btn-switch" onclick="saveAutoSwitchSettings()">保存</button>
                </div>
            </div>
            <div id="countdown-display" class="countdown" style="display:none;">
                下次切换: <span id="next-switch-time">--</span> (剩余 <span id="seconds-until-switch">--</span> 秒)
            </div>
        </div>

        <div style="margin: 15px 0;">
            <button class="button button-primary" onclick="showAddPrefixModal()">➕ 添加新前缀</button>
        </div>

        <div id="prefix-list" class="prefix-list">
            <p style="text-align:center; color:#6b7280; padding:20px;">加载中...</p>
        </div>
    </div>

    <!-- 功能区 -->
    <div class="function-grid">
        <div class="function-card">
            <h3>IP 池管理</h3>
            <div class="form-group">
                <label>目标池大小</label>
                <input type="number" id="target-pool" value="5000" min="100" max="100000">
            </div>
            <button class="button button-primary" onclick="rotatePool()">🔄 轮换 IP 池</button>
            <button class="button button-warning" onclick="updateTargetPool()">📝 更新目标池</button>
        </div>

        <div class="function-card">
            <h3>自动轮换设置</h3>
            <div class="form-group">
                <div class="switch-row">
                    <label>启用自动轮换</label>
                    <label class="switch-toggle">
                        <input type="checkbox" id="auto-rotate-enabled">
                        <span class="slider"></span>
                    </label>
                </div>
            </div>
            <div class="form-group">
                <label>轮换间隔（小时）</label>
                <input type="number" id="rotate-interval" min="1" max="168" value="24">
            </div>
            <button class="button button-primary" onclick="saveAutoRotateSettings()">💾 保存设置</button>
        </div>

        <div class="function-card">
            <h3>端口管理</h3>
            <div class="form-group">
                <label>当前端口数</label>
                <div style="font-size:24px; color:#3b82f6; font-weight:600;">
                    <span id="total-ports">0</span>
                </div>
            </div>
            <button class="button button-primary" onclick="showAddPort()">➕ 添加端口</button>
            <button class="button button-secondary" onclick="showBatchAddPort()">📦 批量添加</button>
            <button class="button button-secondary" onclick="showPortList()">📋 查看列表</button>
        </div>

        <div class="function-card">
            <h3>监听端口添加</h3>
            <div class="form-group">
                <label>端口号</label>
                <input type="number" id="quick-port" placeholder="例如: 10080" min="1024" max="65535">
            </div>
            <div class="form-group">
                <label>用户名</label>
                <input type="text" id="quick-username" placeholder="用户名">
            </div>
            <div class="form-group">
                <label>密码</label>
                <input type="password" id="quick-password" placeholder="密码">
            </div>
            <button class="button button-primary" onclick="quickAddPort()">➕ 快速添加</button>
        </div>
    </div>

    <!-- 性能监控图表 -->
    <div class="chart-container">
        <h3>性能监控 - 实时</h3>
        <canvas id="chart"></canvas>
    </div>

    <!-- 实时连接 -->
    <div class="table-container">
        <div class="table-header">
            <h3>实时连接 <span class="table-badge" id="active-count">0</span></h3>
        </div>
        <table>
            <thead>
                <tr>
                    <th>客户端IP</th>
                    <th>目标地址</th>
                    <th>使用IPv6</th>
                    <th>持续时间</th>
                </tr>
            </thead>
            <tbody id="active-table">
                <tr><td colspan="4" style="text-align:center; color:#6b7280;">暂无活跃连接</td></tr>
            </tbody>
        </table>
    </div>

    <!-- 日志搜索 -->
    <div class="search-container">
        <h3>日志搜索</h3>
        <div class="search-box">
            <input type="text" id="search-query" placeholder="输入目标地址、IP等关键词...">
            <button onclick="searchLogs()">搜索</button>
            <button onclick="clearSearch()" class="button-secondary" style="background:#374151;">清除</button>
        </div>
    </div>

    <!-- 最近连接 -->
    <div class="table-container">
        <div class="table-header">
            <h3>最近连接</h3>
        </div>
        <table>
            <thead>
                <tr>
                    <th>时间</th>
                    <th>客户端IP</th>
                    <th>目标地址</th>
                    <th>使用IPv6</th>
                    <th>状态</th>
                    <th>耗时</th>
                </tr>
            </thead>
            <tbody id="logs-table">
                <tr><td colspan="6" style="text-align:center; color:#6b7280;">暂无连接记录</td></tr>
            </tbody>
        </table>
    </div>
</div>

<!-- 添加前缀弹窗 -->
<div id="addPrefixModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeAddPrefixModal()">&times;</span>
        <h2>➕ 添加新前缀</h2>
        
        <div style="margin-bottom: 20px;">
            <button class="button button-primary" onclick="detectPrefixes()">🔍 自动检测可用前缀</button>
        </div>
        
        <div id="detected-prefixes-list" style="display:none;">
            <h3 style="font-size:14px; margin-bottom:10px;">检测到的可用前缀:</h3>
            <div id="detected-prefixes-content" class="detected-list"></div>
        </div>
        
        <div class="form-group">
            <label>或手动输入 IPv6前缀 (CIDR格式):</label>
            <input type="text" id="new-prefix" placeholder="例如: 2001:db8:1234::/64">
            <div class="info-text">格式: 前缀地址/前缀长度（如 2001:db8::/64）</div>
        </div>
        <button class="button button-primary" onclick="saveAddPrefix()">添加</button>
        <button class="button button-secondary" onclick="closeAddPrefixModal()">取消</button>
        <p id="add-prefix-status" style="margin-top:15px;color:#10b981;"></p>
    </div>
</div>

<!-- 端口列表弹窗 -->
<div id="portListModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closePortListModal()">&times;</span>
        <h2>🔌 端口列表</h2>
        <div id="port-list-content"></div>
    </div>
</div>

<!-- 添加端口弹窗 -->
<div id="addPortModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeAddPortModal()">&times;</span>
        <h2>➕ 添加端口</h2>
        <div class="form-group">
            <label>端口号</label>
            <input type="number" id="add-port-number" min="1024" max="65535" placeholder="1024-65535">
        </div>
        <div class="form-group">
            <label>用户名</label>
            <input type="text" id="add-port-username" placeholder="用户名">
        </div>
        <div class="form-group">
            <label>密码</label>
            <input type="password" id="add-port-password" placeholder="密码">
        </div>
        <button class="button button-primary" onclick="saveAddPort()">添加</button>
        <button class="button button-secondary" onclick="closeAddPortModal()">取消</button>
        <p id="add-status" style="margin-top:15px;color:#10b981;"></p>
    </div>
</div>

<!-- 批量添加端口弹窗 -->
<div id="batchAddPortModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeBatchAddPortModal()">&times;</span>
        <h2>📦 批量添加端口</h2>
        <div class="form-group">
            <label>起始端口</label>
            <input type="number" id="batch-start-port" min="1024" max="65535">
        </div>
        <div class="form-group">
            <label>结束端口</label>
            <input type="number" id="batch-end-port" min="1024" max="65535">
        </div>
        <div class="form-group">
            <label>用户名 (所有端口共用)</label>
            <input type="text" id="batch-username">
        </div>
        <div class="form-group">
            <label>密码 (所有端口共用)</label>
            <input type="password" id="batch-password">
        </div>
        <button class="button button-primary" onclick="saveBatchAddPort()">批量添加</button>
        <button class="button button-secondary" onclick="closeBatchAddPortModal()">取消</button>
        <p id="batch-add-status" style="margin-top:15px;color:#10b981;"></p>
    </div>
</div>

<!-- 编辑端口弹窗 -->
<div id="editPortModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeEditPortModal()">&times;</span>
        <h2>✏️ 修改端口</h2>
        <div class="form-group">
            <label>端口号</label>
            <input type="text" id="edit-port-number" readonly style="background:#1a1f2e;">
        </div>
        <div class="form-group">
            <label>用户名</label>
            <input type="text" id="edit-port-username">
        </div>
        <div class="form-group">
            <label>密码</label>
            <input type="password" id="edit-port-password">
        </div>
        <button class="button button-primary" onclick="saveEditPort()">保存</button>
        <button class="button button-secondary" onclick="closeEditPortModal()">取消</button>
        <p id="edit-port-status" style="margin-top:15px;color:#10b981;"></p>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
let chart;
let searchFilter = '';

async function updateStats() {
    try {
        const stats = await fetch('/api/stats').then(r => r.json());
        document.getElementById('total-conns').textContent = stats.total_conns.toLocaleString();
        document.getElementById('success-conns').textContent = stats.success_conns.toLocaleString();
        document.getElementById('qps').textContent = parseFloat(stats.qps).toFixed(2);
        document.getElementById('success-count').textContent = stats.success_conns.toLocaleString();
        document.getElementById('fail-count').textContent = stats.failed_conns.toLocaleString();
        document.getElementById('process-cpu').textContent = stats.process_cpu.toFixed(1) + ' %';
        document.getElementById('system-cpu').textContent = stats.system_cpu.toFixed(1) + ' %';
        document.getElementById('avg-duration').textContent = stats.avg_duration_ms + ' ms';
        document.getElementById('pool-size').textContent = stats.pool_size.toLocaleString();
        document.getElementById('pool-target').textContent = stats.target_pool.toLocaleString();
        
        const poolPercent = stats.target_pool > 0 ? (stats.pool_size / stats.target_pool * 100) : 0;
        document.getElementById('pool-progress').style.width = Math.min(poolPercent, 100) + '%';
        
        document.getElementById('uptime').textContent = stats.uptime_str;
        document.getElementById('recv-rate').textContent = (stats.recv_rate_mbps * 1024).toFixed(2);
        document.getElementById('send-rate').textContent = (stats.send_rate_mbps * 1024).toFixed(2);
        document.getElementById('total-recv').textContent = stats.total_recv_mb.toFixed(2);
        document.getElementById('total-sent').textContent = stats.total_sent_mb.toFixed(2);
        
        if (stats.current_prefix) {
            document.getElementById('current-prefix').textContent = `#${stats.prefix_index}: ${stats.current_prefix}`;
        }
        document.getElementById('total-prefixes').textContent = stats.total_prefixes || 0;
    } catch (e) {
        console.error('Failed to update stats:', e);
    }
}

async function updateActiveConns() {
    try {
        const conns = await fetch('/api/active').then(r => r.json());
        const tbody = document.getElementById('active-table');
        document.getElementById('active-count').textContent = conns.length;
        
        if (conns.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#6b7280;">暂无活跃连接</td></tr>';
            return;
        }
        
        tbody.innerHTML = conns.map(conn => `
            <tr>
                <td>${conn.client_ip}</td>
                <td>${conn.target}</td>
                <td>${conn.ipv6}</td>
                <td>${conn.duration}</td>
            </tr>
        `).join('');
    } catch (e) {}
}

async function updateLogs() {
    try {
        const logs = await fetch('/api/logs').then(r => r.json());
        const tbody = document.getElementById('logs-table');
        
        const filtered = searchFilter ? 
            logs.filter(log => 
                log.target.toLowerCase().includes(searchFilter.toLowerCase()) ||
                log.client_ip.includes(searchFilter) ||
                log.ipv6.includes(searchFilter)
            ) : logs;
        
        if (filtered.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#6b7280;">暂无连接记录</td></tr>';
            return;
        }
        
        tbody.innerHTML = filtered.slice(0, 50).map(log => `
            <tr>
                <td>${log.time}</td>
                <td>${log.client_ip}</td>
                <td>${log.target}</td>
                <td>${log.ipv6}</td>
                <td class="status-success">${log.status}</td>
                <td>${log.duration}</td>
            </tr>
        `).join('');
    } catch (e) {}
}

function searchLogs() {
    searchFilter = document.getElementById('search-query').value;
    updateLogs();
}

function clearSearch() {
    searchFilter = '';
    document.getElementById('search-query').value = '';
    updateLogs();
}

async function updateChart() {
    try {
        const data = await fetch('/api/chart').then(r => r.json());
        if (!chart) return;
        
        chart.data.labels = data.map(d => d.timestamp);
        chart.data.datasets[0].data = data.map(d => d.qps);
        chart.data.datasets[1].data = data.map(d => d.success_rate);
        chart.data.datasets[2].data = data.map(d => d.active_conns);
        chart.update('none');
    } catch (e) {}
}

function initChart() {
    const ctx = document.getElementById('chart').getContext('2d');
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'QPS',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    yAxisID: 'y',
                    tension: 0.4,
                },
                {
                    label: '成功率 (%)',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    yAxisID: 'y1',
                    tension: 0.4,
                },
                {
                    label: '活跃连接',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    yAxisID: 'y2',
                    tension: 0.4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { 
                    display: true, 
                    position: 'top',
                    labels: { color: '#9ca3af', font: { size: 11 } }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#6b7280', font: { size: 10 } },
                    grid: { color: '#2d3748' }
                },
                y: { 
                    type: 'linear', 
                    display: true, 
                    position: 'left',
                    ticks: { color: '#3b82f6' },
                    grid: { color: '#2d3748' }
                },
                y1: { 
                    type: 'linear', 
                    display: true, 
                    position: 'right',
                    ticks: { color: '#10b981' },
                    grid: { drawOnChartArea: false }
                },
                y2: { 
                    type: 'linear', 
                    display: false
                }
            }
        }
    });
}

async function rotatePool() {
    if (!confirm('确定要轮换IP池吗？')) return;
    try {
        const r = await fetch('/api/rotate', { method: 'POST' }).then(r => r.json());
        alert(r.message);
        updateStats();
    } catch (e) {
        alert('轮换失败');
    }
}

async function updateTargetPool() {
    const target = parseInt(document.getElementById('target-pool').value);
    if (!target || target < 100) {
        alert('目标池大小必须 ≥ 100');
        return;
    }
    // 这里需要添加API接口来更新目标池大小
    alert('目标池更新功能待实现');
}

async function saveAutoRotateSettings() {
    const enabled = document.getElementById('auto-rotate-enabled').checked;
    const hours = parseInt(document.getElementById('rotate-interval').value);
    
    if (!hours || hours < 1 || hours > 168) {
        alert('请输入有效的小时数 (1-168)');
        return;
    }
    
    try {
        const r = await fetch('/api/autorotate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled, hours})
        }).then(r => r.json());
        
        alert(enabled ? '已启用自动轮换' : '已关闭自动轮换');
    } catch (e) {
        alert('保存失败');
    }
}

async function loadPrefixes() {
    try {
        const status = await fetch('/api/prefixes').then(r => r.json());
        
        document.getElementById('auto-switch-enabled').checked = status.auto_switch_enabled;
        document.getElementById('switch-interval').value = status.switch_interval_hours;
        
        if (status.auto_switch_enabled && status.seconds_until_switch > 0) {
            document.getElementById('countdown-display').style.display = 'block';
            document.getElementById('next-switch-time').textContent = status.next_switch_time;
            document.getElementById('seconds-until-switch').textContent = status.seconds_until_switch;
        } else {
            document.getElementById('countdown-display').style.display = 'none';
        }
        
        const listDiv = document.getElementById('prefix-list');
        if (status.prefixes.length === 0) {
            listDiv.innerHTML = '<p style="text-align:center; color:#6b7280;">暂无前缀配置</p>';
            return;
        }
        
        listDiv.innerHTML = status.prefixes.map(prefix => {
            const activeClass = prefix.is_active ? 'active' : '';
            const badge = prefix.is_active ? 
                '<span class="prefix-badge badge-active">✓ 当前</span>' : '';
            
            const actions = prefix.is_active ?
                `<button class="btn-sm" disabled>使用中</button>` :
                `<button class="btn-sm btn-switch" onclick="switchPrefix(${prefix.index})">切换</button>
                 <button class="btn-sm btn-delete" onclick="deletePrefix(${prefix.index})">删除</button>`;
            
            return `
                <div class="prefix-item ${activeClass}">
                    <div>
                        <div class="prefix-title">${badge} 前缀 #${prefix.index}</div>
                        <div class="prefix-meta">${prefix.prefix}</div>
                    </div>
                    <div class="prefix-actions">${actions}</div>
                </div>
            `;
        }).join('');
        
    } catch (e) {
        console.error('加载前缀失败:', e);
    }
}

async function switchPrefix(index) {
    if (!confirm(`确定要切换到前缀 #${index} 吗？`)) return;
    
    try {
        const r = await fetch('/api/prefixes/switch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({index})
        }).then(r => r.json());
        
        alert(r.message);
        loadPrefixes();
        updateStats();
    } catch (e) {
        alert('切换失败');
    }
}

async function deletePrefix(index) {
    if (!confirm(`确定要删除前缀 #${index} 吗？`)) return;
    
    try {
        const r = await fetch('/api/prefixes/delete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({index})
        }).then(r => r.json());
        
        alert(r.message);
        loadPrefixes();
    } catch (e) {
        alert('删除失败');
    }
}

function showAddPrefixModal() {
    const modal = document.getElementById('addPrefixModal');
    document.getElementById('new-prefix').value = '';
    document.getElementById('add-prefix-status').textContent = '';
    document.getElementById('detected-prefixes-list').style.display = 'none';
    modal.style.display = 'block';
}

function closeAddPrefixModal() {
    document.getElementById('addPrefixModal').style.display = 'none';
}

async function detectPrefixes() {
    try {
        const result = await fetch('/api/prefixes/detect').then(r => r.json());
        const listDiv = document.getElementById('detected-prefixes-list');
        const contentDiv = document.getElementById('detected-prefixes-content');
        
        if (result.available.length === 0) {
            contentDiv.innerHTML = '<p style="text-align:center; color:#6b7280; padding:20px;">未检测到新的可用前缀</p>';
            listDiv.style.display = 'block';
            return;
        }
        
        contentDiv.innerHTML = result.available.map(p => `
            <div class="detected-item">
                <div class="detected-info">
                    <strong>${p.Prefix}</strong><br>
                    <small>📡 ${p.Interface} | 示例: ${p.SampleIP} | 长度: /${p.PrefixLen}</small>
                </div>
                <button class="btn-sm btn-switch" onclick="addDetectedPrefix('${p.Prefix}')">添加</button>
            </div>
        `).join('');
        
        listDiv.style.display = 'block';
    } catch (e) {
        alert('检测失败');
    }
}

async function addDetectedPrefix(prefix) {
    try {
        const r = await fetch('/api/prefixes/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({prefix})
        }).then(r => r.json());
        
        alert(r.message);
        closeAddPrefixModal();
        loadPrefixes();
    } catch (e) {
        alert('添加失败');
    }
}

async function saveAddPrefix() {
    const prefix = document.getElementById('new-prefix').value.trim();
    
    if (!prefix) {
        alert('请输入IPv6前缀');
        return;
    }
    
    try {
        const r = await fetch('/api/prefixes/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({prefix})
        }).then(r => r.json());
        
        document.getElementById('add-prefix-status').textContent = '✅ ' + r.message;
        setTimeout(() => {
            closeAddPrefixModal();
            loadPrefixes();
        }, 1500);
    } catch (e) {
        alert('添加失败');
    }
}

async function toggleAutoSwitch() {
    const enabled = document.getElementById('auto-switch-enabled').checked;
    const hours = parseInt(document.getElementById('switch-interval').value) || 24;
    
    try {
        const r = await fetch('/api/prefixes/auto-switch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled, hours})
        }).then(r => r.json());
        
        alert(enabled ? '已启用自动切换' : '已关闭自动切换');
        loadPrefixes();
    } catch (e) {
        alert('设置失败');
        document.getElementById('auto-switch-enabled').checked = !enabled;
    }
}

async function saveAutoSwitchSettings() {
    const enabled = document.getElementById('auto-switch-enabled').checked;
    const hours = parseInt(document.getElementById('switch-interval').value);
    
    if (!hours || hours < 1 || hours > 168) {
        alert('请输入有效的小时数 (1-168)');
        return;
    }
    
    try {
        const r = await fetch('/api/prefixes/auto-switch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled, hours})
        }).then(r => r.json());
        
        alert('设置已保存');
        loadPrefixes();
    } catch (e) {
        alert('保存失败');
    }
}

async function quickAddPort() {
    const port = document.getElementById('quick-port').value;
    const username = document.getElementById('quick-username').value;
    const password = document.getElementById('quick-password').value;
    
    if (!port || !username || !password) {
        alert('请填写所有字段');
        return;
    }
    
    try {
        const r = await fetch('/api/ports/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({port, username, password})
        }).then(r => r.json());
        
        alert(r.message);
        document.getElementById('quick-port').value = '';
        document.getElementById('quick-username').value = '';
        document.getElementById('quick-password').value = '';
        updatePortCount();
    } catch (e) {
        alert('添加失败');
    }
}

function showPortList() {
    fetch('/api/ports')
        .then(r => r.json())
        .then(ports => {
            const modal = document.getElementById('portListModal');
            const content = document.getElementById('port-list-content');
            
            if (ports.length === 0) {
                content.innerHTML = '<p style="text-align:center; color:#6b7280; padding:20px;">暂无额外端口</p>';
            } else {
                content.innerHTML = ports.map(p => `
                    <div class="detected-item">
                        <div class="detected-info">
                            <strong>端口 ${p.port}</strong><br>
                            <small>用户: ${p.username}</small>
                        </div>
                        <div style="display:flex; gap:8px;">
                            <button class="btn-sm btn-switch" onclick="editPort('${p.port}')">编辑</button>
                            <button class="btn-sm btn-delete" onclick="deletePort('${p.port}')">删除</button>
                        </div>
                    </div>
                `).join('');
            }
            
            modal.style.display = 'block';
        });
}

function closePortListModal() {
    document.getElementById('portListModal').style.display = 'none';
}

function showAddPort() {
    const modal = document.getElementById('addPortModal');
    document.getElementById('add-port-number').value = '';
    document.getElementById('add-port-username').value = '';
    document.getElementById('add-port-password').value = '';
    document.getElementById('add-status').textContent = '';
    modal.style.display = 'block';
}

function closeAddPortModal() {
    document.getElementById('addPortModal').style.display = 'none';
}

async function saveAddPort() {
    const port = document.getElementById('add-port-number').value;
    const username = document.getElementById('add-port-username').value;
    const password = document.getElementById('add-port-password').value;
    
    if (!port || !username || !password) {
        alert('请填写所有字段');
        return;
    }
    
    try {
        const r = await fetch('/api/ports/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({port, username, password})
        }).then(r => r.json());
        
        document.getElementById('add-status').textContent = '✅ ' + r.message;
        setTimeout(() => {
            closeAddPortModal();
            updatePortCount();
        }, 1500);
    } catch (e) {
        alert('添加失败');
    }
}

function showBatchAddPort() {
    const modal = document.getElementById('batchAddPortModal');
    document.getElementById('batch-start-port').value = '';
    document.getElementById('batch-end-port').value = '';
    document.getElementById('batch-username').value = '';
    document.getElementById('batch-password').value = '';
    document.getElementById('batch-add-status').textContent = '';
    modal.style.display = 'block';
}

function closeBatchAddPortModal() {
    document.getElementById('batchAddPortModal').style.display = 'none';
}

async function saveBatchAddPort() {
    const startPort = parseInt(document.getElementById('batch-start-port').value);
    const endPort = parseInt(document.getElementById('batch-end-port').value);
    const username = document.getElementById('batch-username').value;
    const password = document.getElementById('batch-password').value;
    
    if (!startPort || !endPort || !username || !password) {
        alert('请填写所有字段');
        return;
    }
    
    if (startPort > endPort) {
        alert('起始端口不能大于结束端口');
        return;
    }
    
    if (endPort - startPort > 100) {
        alert('一次最多添加100个端口');
        return;
    }
    
    try {
        const r = await fetch('/api/ports/batch', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({start_port: startPort, end_port: endPort, username, password})
        }).then(r => r.json());
        
        document.getElementById('batch-add-status').textContent = '✅ ' + r.message;
        setTimeout(() => {
            closeBatchAddPortModal();
            updatePortCount();
        }, 2000);
    } catch (e) {
        alert('批量添加失败');
    }
}

function editPort(port) {
    const modal = document.getElementById('editPortModal');
    document.getElementById('edit-port-number').value = port;
    document.getElementById('edit-port-status').textContent = '';
    
    fetch('/api/ports')
        .then(r => r.json())
        .then(ports => {
            const portInfo = ports.find(p => p.port === port);
            if (portInfo) {
                document.getElementById('edit-port-username').value = portInfo.username;
                document.getElementById('edit-port-password').value = '';
            }
        });
    
    modal.style.display = 'block';
}

function closeEditPortModal() {
    document.getElementById('editPortModal').style.display = 'none';
}

async function saveEditPort() {
    const port = document.getElementById('edit-port-number').value;
    const username = document.getElementById('edit-port-username').value;
    const password = document.getElementById('edit-port-password').value;
    
    if (!username || !password) {
        alert('请输入用户名和密码');
        return;
    }
    
    try {
        const r = await fetch('/api/changepassword', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({port, username, password})
        }).then(r => r.json());
        
        document.getElementById('edit-port-status').textContent = '✅ ' + r.message;
        setTimeout(() => {
            closeEditPortModal();
        }, 1500);
    } catch (e) {
        alert('保存失败');
    }
}

async function deletePort(port) {
    if (!confirm(`确定要删除端口 ${port} 吗？`)) return;
    
    try {
        const r = await fetch('/api/ports/delete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({port})
        }).then(r => r.json());
        
        alert(r.message);
        showPortList();
        updatePortCount();
    } catch (e) {
        alert('删除失败');
    }
}

async function updatePortCount() {
    try {
        const ports = await fetch('/api/ports').then(r => r.json());
        document.getElementById('total-ports').textContent = ports.length;
    } catch (e) {}
}

window.onclick = function(event) {
    const modals = ['addPrefixModal', 'portListModal', 'addPortModal', 'batchAddPortModal', 'editPortModal'];
    modals.forEach(modalId => {
        const modal = document.getElementById(modalId);
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

document.getElementById('search-query').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') searchLogs();
});

initChart();
setInterval(updateStats, 3000);
setInterval(updateChart, 5000);
setInterval(updateLogs, 5000);
setInterval(updateActiveConns, 3000);
setInterval(updatePortCount, 10000);
setInterval(loadPrefixes, 10000);
updateStats();
updateChart();
updateLogs();
updateActiveConns();
updatePortCount();
loadPrefixes();
</script>
</body>
</html>
HTMLEOF

print_success "前端完成"
echo ""

# --- 步骤 5: 编译 ---
echo "--- 步骤 5: 编译 ---"

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
Description=IPv6 Proxy v8.1 Multi-Prefix Auto-Detect
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

sleep 2
if systemctl is-active --quiet ipv6-proxy; then
    print_success "服务启动成功"
else
    print_warning "服务启动可能失败，请检查："
    echo "   systemctl status ipv6-proxy"
fi

echo ""
echo "================================================"
echo "🎉 IPv6 代理 v8.1 多前缀智能版 安装成功！"
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
echo "🆕 v8.1 新功能:"
echo "  ✅ 自动检测系统所有IPv6前缀"
echo "  ✅ 智能选择和配置多前缀"
echo "  ✅ Web界面一键检测可用前缀"
echo "  ✅ 支持手动/自动切换前缀"
echo "  ✅ 实时倒计时显示"
echo "  ✅ 循环轮换所有配置的前缀"
echo ""
echo "管理命令:"
echo "  systemctl status ipv6-proxy     # 查看状态"
echo "  systemctl restart ipv6-proxy    # 重启服务"
echo "  systemctl stop ipv6-proxy       # 停止服务"
echo "  journalctl -u ipv6-proxy -f     # 查看日志"
echo ""
echo "配置文件: $INSTALL_DIR/config.json"
echo ""
echo "🎊 享受你的智能多前缀 IPv6 代理服务！"
echo "================================================"
