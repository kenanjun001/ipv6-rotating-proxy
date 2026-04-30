#!/bin/bash
# IPv6 代理 v7.6
# 支持 HTTP CONNECT 与 SOCKS5，同一端口自动识别协议；启动时清理旧的 /128 IPv6。

INSTALL_DIR="/opt/ipv6-proxy"
BUILD_DIR="/root/ipv6-proxy-build"
GO_VERSION="1.21.5"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"
export PATH=/usr/local/go/bin:$PATH
PURGE_INSTALL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
print_success(){ echo -e "${GREEN}[成功] $1${NC}"; }
print_error(){ echo -e "${RED}[错误] $1${NC}"; }
print_warning(){ echo -e "${YELLOW}[警告] $1${NC}"; }
print_info(){ echo -e "${BLUE}[信息] $1${NC}"; }

if [ "$(id -u)" -ne 0 ]; then print_error "需要 root 权限，请使用 sudo"; exit 1; fi

echo "============================================="
echo "=== IPv6 代理 v7.6 完全集成版 ==="
echo "============================================="

web_port_open(){
  local port="$1"
  [ -n "$port" ] || return 1
  timeout 3 bash -c ":</dev/tcp/127.0.0.1/$port" >/dev/null 2>&1
}

wait_web_port(){
  local port="$1"
  local max_wait="${2:-180}"
  local waited=0
  while [ $waited -lt $max_wait ]; do
    if web_port_open "$port"; then
      return 0
    fi
    if [ $((waited % 10)) -eq 0 ]; then
      print_info "等待 Web 面板端口 ${port} 就绪... (${waited}/${max_wait} 秒)"
    fi
    sleep 2
    waited=$((waited+2))
  done
  return 1
}

if [ -x "$INSTALL_DIR/ipv6-proxy" ] && [ -f /etc/systemd/system/ipv6-proxy.service ]; then
  print_info "检测到 IPv6 代理已安装，正在检查 Web 面板"
  systemctl daemon-reload
  systemctl enable ipv6-proxy >/dev/null 2>&1 || true
  PROXY_PORT=$(grep -oP '"port"\s*:\s*"\K[^"]+' "$INSTALL_DIR/config.json" 2>/dev/null || echo 1080)
  WEB_PORT=$(grep -oP '"web_port"\s*:\s*"\K[^"]+' "$INSTALL_DIR/config.json" 2>/dev/null || echo 8080)
  if systemctl is-active --quiet ipv6-proxy; then
    print_info "服务正在运行"
  else
    print_info "服务未运行，正在启动"
    systemctl start ipv6-proxy >/dev/null 2>&1 || true
  fi
  if ! wait_web_port "$WEB_PORT" 60; then
    print_warning "Web 面板端口 ${WEB_PORT} 未响应，尝试重启服务"
    systemctl restart ipv6-proxy >/dev/null 2>&1 || true
    wait_web_port "$WEB_PORT" 120 || true
  fi
  IP=$(curl -s ifconfig.me 2>/dev/null || echo "你的服务器IP")
  if web_port_open "$WEB_PORT"; then
    print_success "Web 面板正常"
  else
    print_warning "Web 面板仍不可访问"
  fi
  echo "当前 Web 面板: http://${IP}:${WEB_PORT}"
  echo "当前 HTTP 代理: http://proxy:proxy@${IP}:${PROXY_PORT}"
  echo "当前 SOCKS5 代理: socks5://proxy:proxy@${IP}:${PROXY_PORT}"
  if [ -t 0 ]; then
    echo ""
    echo "请选择操作:"
    echo "  1) 跳过安装，保持现有服务"
    echo "  2) 更新/重装，保留现有配置文件"
    echo "  3) 卸载后安装，删除旧程序和配置后重新配置"
    echo "  4) 退出"
    read -r -p "输入选择 (默认 1): " INSTALL_CHOICE
    INSTALL_CHOICE=${INSTALL_CHOICE:-1}
  else
    INSTALL_CHOICE=1
  fi
  case "$INSTALL_CHOICE" in
    1)
      print_success "已选择跳过安装"
      exit 0
      ;;
    2)
      print_warning "已选择更新/重装，将保留 $INSTALL_DIR/config.json"
      ;;
    3)
      print_warning "已选择卸载后安装，将删除 $INSTALL_DIR 和旧配置"
      PURGE_INSTALL=1
      ;;
    4)
      print_info "已退出"
      exit 0
      ;;
    *)
      print_warning "无效选择，默认跳过安装"
      exit 0
      ;;
  esac
  if [ "$INSTALL_CHOICE" != "2" ] && [ "$INSTALL_CHOICE" != "3" ]; then
    exit 0
  fi
fi

handle_apt_locks(){
  local waited=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if [ $waited -ge 60 ]; then
      print_warning "包管理锁等待超时，尝试清理"
      killall apt apt-get dpkg unattended-upgr 2>/dev/null || true
      rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* /var/lib/dpkg/lock-frontend
      dpkg --configure -a 2>/dev/null || true
      return
    fi
    sleep 2; waited=$((waited+2))
  done
}

print_info "清理旧服务"
systemctl stop ipv6-proxy.service >/dev/null 2>&1 || true
systemctl disable ipv6-proxy.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/ipv6-proxy.service
if [ "$PURGE_INSTALL" = "1" ]; then
  rm -rf "$INSTALL_DIR"
fi
rm -rf "$BUILD_DIR"
systemctl daemon-reload

print_info "安装依赖和 Go"
if command -v wget >/dev/null 2>&1 && command -v update-ca-certificates >/dev/null 2>&1; then
  print_info "系统依赖已存在，跳过 apt 安装"
else
  handle_apt_locks
  apt-get update >/dev/null 2>&1 || apt-get update --fix-missing >/dev/null 2>&1 || true
  apt-get install -y wget ca-certificates >/dev/null 2>&1 || { print_error "安装依赖失败"; exit 1; }
fi
if [ ! -x /usr/local/go/bin/go ] || ! /usr/local/go/bin/go version | grep -q "$GO_VERSION"; then
  rm -rf /usr/local/go
  wget -q "$GO_URL" -O "/tmp/$GO_TAR" || { print_error "下载 Go 失败"; exit 1; }
  tar -C /usr/local -xzf "/tmp/$GO_TAR" && rm -f "/tmp/$GO_TAR"
else
  print_info "Go $GO_VERSION 已存在，跳过下载"
fi

print_info "创建源码"
mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR" || exit 1
cat <<'GOEOF' > main.go
package main

import (
 "bufio"; "context"; "crypto/rand"; "crypto/subtle"; "encoding/base64"; "encoding/binary"; "encoding/json"; "errors"; "fmt"; "io"; "log"; mrand "math/rand"; "net"; "net/http"; "os"; "os/signal"; "path/filepath"; "sort"; "strconv"; "strings"; "sync"; "sync/atomic"; "syscall"; "time"
 "github.com/vishvananda/netlink"
)

type Config struct {
	Port            string       `json:"port"`
	WebPort         string       `json:"web_port"`
	WebUsername     string       `json:"web_username"`
	WebPassword     string       `json:"web_password"`
	Username        string       `json:"username"`
	Password        string       `json:"password"`
	IPv6Prefix      string       `json:"ipv6_prefix"`
	NextHopAddr     string       `json:"nexthop_addr"`
	Interface       string       `json:"interface"`
	InitialPool     int          `json:"initial_pool"`
	TargetPool      int          `json:"target_pool"`
	AutoRotate      bool         `json:"auto_rotate"`
	AutoRotateHours int          `json:"auto_rotate_hours"`
	AutoClean       bool         `json:"auto_clean"`
	Ports           []PortConfig `json:"ports"`
}
type PortConfig struct {
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
	Created  string `json:"created"`
}
type Stats struct{ StartTime time.Time; TotalConns,ActiveConns,SuccessConns,FailedConns,TimeoutConns,PoolSize,TotalBytesRecv,TotalBytesSent int64 }
type ConnLog struct{ Time,ClientIP,Target,IPv6,Status,Duration string }
type ActiveConn struct{ ID,ClientIP,Target,IPv6,Duration string; StartTime time.Time }

var config Config; var stats Stats
var ipv6Pool []net.IP; var ipv6PoolIndex map[string]int; var poolLock sync.RWMutex
var logs []*ConnLog; var logsLock sync.RWMutex; var failLogs []*ConnLog; var failLogsLock sync.RWMutex
var active=map[string]*ActiveConn{}; var activeLock sync.RWMutex
var iface netlink.Link; var prefixIP net.IP; var prefixNet *net.IPNet; var discardQueue chan net.IP
var rng=mrand.New(mrand.NewSource(time.Now().UnixNano())); var rngLock sync.Mutex
var configFilePath,indexHTMLPath string

func readLine(prompt,def string) string{ r:=bufio.NewReader(os.Stdin); if def==""{fmt.Printf("%s: ",prompt)}else{fmt.Printf("%s (默认 %s): ",prompt,def)}; s,_:=r.ReadString('\n'); s=strings.TrimSpace(s); if s==""{return def}; return s }
func readInt(prompt string,def int) int{ for{ n,err:=strconv.Atoi(readLine(prompt,strconv.Itoa(def))); if err==nil && n>=0{return n} } }
func readChoice(max int) int{ for{ n,err:=strconv.Atoi(readLine(fmt.Sprintf("选择 (1-%d)",max),"")); if err==nil && n>=1 && n<=max{return n} } }
func saveConfig() error{ b,err:=json.MarshalIndent(config,"","  "); if err!=nil{return err}; return os.WriteFile(configFilePath,b,0600) }
func loadConfig() error{ b,err:=os.ReadFile(configFilePath); if err!=nil{return err}; return json.Unmarshal(b,&config) }

func selectInterface()(netlink.Link,error){ links,err:=netlink.LinkList(); if err!=nil{return nil,err}; var arr []netlink.Link; for _,l:=range links{ if l.Attrs().Flags&net.FlagUp!=0 && l.Attrs().Flags&net.FlagLoopback==0{ arr=append(arr,l) } }; if len(arr)==0{return nil,errors.New("无可用网卡")}; log.Println("可用网卡:"); for i,l:=range arr{log.Printf("  %d: %s",i+1,l.Attrs().Name)}; return arr[readChoice(len(arr))-1],nil }
func selectPrefix(link netlink.Link)(string,error){ addrs,err:=netlink.AddrList(link,netlink.FAMILY_V6); if err!=nil{return "",err}; set:=map[string]bool{}; for _,a:=range addrs{ if a.IPNet!=nil && a.IP.IsGlobalUnicast(){ ones,bits:=a.IPNet.Mask.Size(); if bits==128 && ones<=64{ m:=a.IP.Mask(net.CIDRMask(ones,128)); set[fmt.Sprintf("%s/%d",m.String(),ones)]=true } } }; if len(set)==0{return readLine("请输入 IPv6 前缀，例如 2605:6400:408c::/48",""),nil}; var arr []string; for p:=range set{arr=append(arr,p)}; sort.Strings(arr); log.Println("检测到 IPv6 前缀:"); for i,p:=range arr{log.Printf("  %d: %s",i+1,p)}; return arr[readChoice(len(arr))-1],nil }
func firstSetup() error{ config.WebUsername=readLine("Web 账号","admin"); config.WebPassword=readLine("Web 密码","admin123"); config.Port=readLine("代理端口","1080"); config.WebPort=readLine("Web 端口","8080"); config.Username=readLine("代理用户名","proxy"); config.Password=readLine("代理密码","proxy"); l,err:=selectInterface(); if err!=nil{return err}; config.Interface=l.Attrs().Name; p,err:=selectPrefix(l); if err!=nil{return err}; config.IPv6Prefix=p; config.NextHopAddr=readLine("下一跳地址，没有则留空",""); config.InitialPool=readInt("初始 IP 数量",1); config.TargetPool=readInt("目标 IP 数量",1); if config.TargetPool<config.InitialPool{config.TargetPool=config.InitialPool}; config.AutoRotate=strings.ToLower(readLine("启用自动轮换? (y/n)","n"))=="y"; if config.AutoRotate{config.AutoRotateHours=readInt("轮换间隔小时",6)}; config.AutoClean=strings.ToLower(readLine("启用失败 IP 自动清理? (y/n)","y"))=="y"; return saveConfig() }
GOEOF
cat <<'GOEOF' >> main.go
func genIP() net.IP{ ip:=make(net.IP,16); copy(ip,prefixIP.To16()); ones,_:=prefixNet.Mask.Size(); b:=ones/8; if b<16{_,_=rand.Read(ip[b:])}; if ones%8!=0 && b<16{mask:=byte(0xff<<(8-ones%8)); ip[b]=(prefixIP[b]&mask)|(ip[b]&^mask)}; return ip }
func addIP(ip net.IP) error{ return netlink.AddrAdd(iface,&netlink.Addr{IPNet:&net.IPNet{IP:ip,Mask:net.CIDRMask(128,128)},Flags:syscall.IFA_F_NODAD}) }
func delIP(ip net.IP){ _=netlink.AddrDel(iface,&netlink.Addr{IPNet:&net.IPNet{IP:ip,Mask:net.CIDRMask(128,128)}}) }
func cleanupStale(){ addrs,err:=netlink.AddrList(iface,netlink.FAMILY_V6); if err!=nil{log.Printf("启动清理旧 IPv6 失败: %v",err);return}; var nh net.IP; if config.NextHopAddr!=""{nh=net.ParseIP(config.NextHopAddr)}; n:=0; for _,a:=range addrs{ if a.IPNet==nil||a.IP==nil{continue}; ones,bits:=a.IPNet.Mask.Size(); if bits!=128||ones!=128||!prefixNet.Contains(a.IP){continue}; if nh!=nil&&a.IP.Equal(nh){continue}; if netlink.AddrDel(iface,&a)==nil{n++} }; log.Printf("启动清理旧 IPv6: %d 个",n) }
func initPool() error{ log.Printf("初始化 IP 池: %d 个",config.InitialPool); ipv6Pool=[]net.IP{}; ipv6PoolIndex=map[string]int{}; if config.InitialPool<1{atomic.StoreInt64(&stats.PoolSize,0); log.Printf("初始 IP 数量为 0，等待 Web 面板添加"); return nil}; for i:=0;i<config.InitialPool;i++{ ip:=genIP(); if addIP(ip)==nil{ipv6PoolIndex[ip.String()]=len(ipv6Pool); ipv6Pool=append(ipv6Pool,ip)}; if (i+1)%100==0||i+1==config.InitialPool{fmt.Printf("\r进度: %d/%d",i+1,config.InitialPool)} }; fmt.Println(); atomic.StoreInt64(&stats.PoolSize,int64(len(ipv6Pool))); if len(ipv6Pool)==0{return errors.New("没有成功添加 IPv6")}; return nil }
func addOnePoolIP() bool{ ip:=genIP(); if addIP(ip)!=nil{return false}; poolLock.Lock(); ipv6PoolIndex[ip.String()]=len(ipv6Pool); ipv6Pool=append(ipv6Pool,ip); n:=len(ipv6Pool); poolLock.Unlock(); atomic.StoreInt64(&stats.PoolSize,int64(n)); return true }
func addPoolIPs(count int) int{ if count<1{return 0}; ok:=0; for i:=0;i<count;i++{if addOnePoolIP(){ok++}}; if ok>0{config.TargetPool+=ok; config.InitialPool=config.TargetPool; _=saveConfig()}; return ok }
func setPoolTarget(count int) int{ if count<1{count=1}; config.TargetPool=count; config.InitialPool=count; poolLock.Lock(); remove:=[]net.IP{}; if len(ipv6Pool)>count{remove=append(remove,ipv6Pool[count:]...); ipv6Pool=ipv6Pool[:count]}; ipv6PoolIndex=map[string]int{}; for i,ip:=range ipv6Pool{ipv6PoolIndex[ip.String()]=i}; n:=len(ipv6Pool); poolLock.Unlock(); for _,ip:=range remove{delIP(ip)}; atomic.StoreInt64(&stats.PoolSize,int64(n)); _=saveConfig(); for i:=0;i<50&&int(atomic.LoadInt64(&stats.PoolSize))<config.TargetPool;i++{addOnePoolIP()}; return int(atomic.LoadInt64(&stats.PoolSize)) }
func clearAllIPv6() int{ config.TargetPool=0; config.InitialPool=0; _=saveConfig(); poolLock.Lock(); poolIPs:=append([]net.IP(nil),ipv6Pool...); ipv6Pool=[]net.IP{}; ipv6PoolIndex=map[string]int{}; poolLock.Unlock(); deleted:=0; seen:=map[string]bool{}; for _,ip:=range poolIPs{delIP(ip); seen[ip.String()]=true; deleted++}; addrs,err:=netlink.AddrList(iface,netlink.FAMILY_V6); if err==nil{var nh net.IP; if config.NextHopAddr!=""{nh=net.ParseIP(config.NextHopAddr)}; for _,a:=range addrs{if a.IPNet==nil||a.IP==nil{continue}; ones,bits:=a.IPNet.Mask.Size(); if bits!=128||ones!=128||!prefixNet.Contains(a.IP){continue}; if nh!=nil&&a.IP.Equal(nh){continue}; if seen[a.IP.String()]{continue}; if netlink.AddrDel(iface,&a)==nil{deleted++}}}; atomic.StoreInt64(&stats.PoolSize,0); return deleted }
func backgroundFill(ctx context.Context){ t:=time.NewTicker(100*time.Millisecond); defer t.Stop(); for{select{case<-ctx.Done():return; case<-t.C: for i:=0;i<50 && int(atomic.LoadInt64(&stats.PoolSize))<config.TargetPool;i++{addOnePoolIP()} } } }
func rotatePool(){ want:=config.TargetPool; if want<1{want=config.InitialPool}; if want<1{log.Printf("轮换跳过: 目标 IP 数量为 0"); return}; log.Printf("开始轮换 IPv6 池，生成 %d 个新地址",want); newIPs:=[]net.IP{}; newIndex:=map[string]int{}; for i:=0;i<want;i++{ip:=genIP(); if addIP(ip)==nil{newIndex[ip.String()]=len(newIPs); newIPs=append(newIPs,ip)}}; if len(newIPs)==0{log.Printf("轮换失败: 新地址添加失败"); return}; poolLock.Lock(); old:=ipv6Pool; ipv6Pool=newIPs; ipv6PoolIndex=newIndex; poolLock.Unlock(); atomic.StoreInt64(&stats.PoolSize,int64(len(newIPs))); log.Printf("轮换完成: %d 个新 IP，旧 IP 将在 30 分钟后清理",len(newIPs)); go func(ips []net.IP){time.Sleep(30*time.Minute); for _,ip:=range ips{delIP(ip)}}(old) }
func autoRotate(ctx context.Context){ if !config.AutoRotate{return}; hours:=config.AutoRotateHours; if hours<1{hours=6}; t:=time.NewTicker(time.Duration(hours)*time.Hour); defer t.Stop(); log.Printf("自动轮换已启用，每 %d 小时轮换一次",hours); for{select{case<-ctx.Done():return; case<-t.C: rotatePool()}} }
func getIP() net.IP{ poolLock.RLock(); defer poolLock.RUnlock(); if len(ipv6Pool)==0{return nil}; rngLock.Lock(); i:=rng.Intn(len(ipv6Pool)); rngLock.Unlock(); return append(net.IP(nil),ipv6Pool[i]...) }
func removePoolIP(ip net.IP) bool{ if ip==nil{return false}; key:=ip.String(); poolLock.Lock(); idx,ok:=ipv6PoolIndex[key]; if ok{last:=len(ipv6Pool)-1; if idx>=0&&idx<=last{if idx!=last{ipv6Pool[idx]=ipv6Pool[last]; ipv6PoolIndex[ipv6Pool[idx].String()]=idx}; ipv6Pool=ipv6Pool[:last]}; delete(ipv6PoolIndex,key)}; n:=len(ipv6Pool); poolLock.Unlock(); if ok{atomic.StoreInt64(&stats.PoolSize,int64(n)); delIP(ip)}; return ok }
type DialTarget struct{ Network,Address string; UseIPv6 bool }
func resolveTargets(ctx context.Context,host string,port uint16)([]DialTarget,error){ ps:=strconv.Itoa(int(port)); if ip:=net.ParseIP(host); ip!=nil{if ip.To4()!=nil{return []DialTarget{{"tcp4",net.JoinHostPort(ip.String(),ps),false}},nil}; return []DialTarget{{"tcp6",net.JoinHostPort(ip.String(),ps),true}},nil}; addrs,err:=net.DefaultResolver.LookupIPAddr(ctx,host); if err!=nil{return nil,err}; seen:=map[string]bool{}; v6:=[]DialTarget{}; v4:=[]DialTarget{}; for _,a:=range addrs{if a.IP==nil{continue}; addr:=net.JoinHostPort(a.IP.String(),ps); if seen[addr]{continue}; seen[addr]=true; if a.IP.To4()==nil{v6=append(v6,DialTarget{"tcp6",addr,true})}else{v4=append(v4,DialTarget{"tcp4",addr,false})}}; if len(v6)>0{return v6,nil}; if len(v4)>0{return v4,nil}; return nil,fmt.Errorf("target %s has no available IP record",host)}
func addLog(c,t,ip,st string,d time.Duration){ x:=&ConnLog{time.Now().Format("15:04:05"),c,t,ip,st,fmt.Sprintf("%.2fs",d.Seconds())}; logsLock.Lock(); logs=append(logs,x); if len(logs)>10{logs=logs[len(logs)-10:]}; logsLock.Unlock(); if !strings.Contains(st,"成功"){failLogsLock.Lock(); failLogs=append(failLogs,x); if len(failLogs)>10{failLogs=failLogs[len(failLogs)-10:]}; failLogsLock.Unlock()} }
func auth(port,u,p string) bool{ eu,ep:=config.Username,config.Password; if port!=config.Port{ok:=false; for _,x:=range config.Ports{if x.Port==port&&x.Enabled{eu=x.Username; ep=x.Password; ok=true; break}}; if !ok{return false}}; return subtle.ConstantTimeCompare([]byte(u),[]byte(eu))==1&&subtle.ConstantTimeCompare([]byte(p),[]byte(ep))==1 }
func copyConn(dst,src net.Conn,deadline time.Time,counter *int64,wg *sync.WaitGroup){ defer wg.Done(); buf:=make([]byte,65536); for{src.SetReadDeadline(deadline); dst.SetWriteDeadline(deadline); n,er:=src.Read(buf); if n>0{atomic.AddInt64(counter,int64(n)); if _,ew:=dst.Write(buf[:n]); ew!=nil{return}}; if er!=nil{return}} }
func proxy(client net.Conn,host string,port uint16,isSocks bool){ start:=time.Now(); cip:=client.RemoteAddr().String(); target:=net.JoinHostPort(host,strconv.Itoa(int(port))); id:=fmt.Sprintf("%s-%d",cip,time.Now().UnixNano()); activeLock.Lock(); active[id]=&ActiveConn{ID:id,ClientIP:cip,Target:target,IPv6:"dialing",StartTime:start}; activeLock.Unlock(); defer func(){activeLock.Lock(); delete(active,id); activeLock.Unlock()}(); ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second); defer cancel(); targets,err:=resolveTargets(ctx,host,port); if err!=nil{st:="failed: "+err.Error(); if len(st)>80{st=st[:80]}; addLog(cip,target,"none",st,time.Since(start)); if isSocks{client.Write([]byte{5,4,0,1,0,0,0,0,0,0})}else{client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))}; atomic.AddInt64(&stats.FailedConns,1); return}; maxAttempts:=len(targets); if maxAttempts<3{maxAttempts=3}; if maxAttempts>6{maxAttempts=6}; var remote net.Conn; var lastErr error; lastIP:="none"; for attempt:=0; attempt<maxAttempts; attempt++{dt:=targets[attempt%len(targets)]; d:=net.Dialer{Timeout:15*time.Second}; logIP:="IPv4"; var ip net.IP; if dt.UseIPv6{ip=getIP(); if ip==nil{lastErr=errors.New("no available IP"); break}; d.LocalAddr=&net.TCPAddr{IP:ip}; logIP=ip.String()}; lastIP=logIP; activeLock.Lock(); if ac:=active[id]; ac!=nil{ac.IPv6=logIP}; activeLock.Unlock(); remote,err=d.DialContext(ctx,dt.Network,dt.Address); if err==nil{break}; lastErr=err; if dt.UseIPv6&&config.AutoClean{removePoolIP(ip)}; time.Sleep(100*time.Millisecond) }; if remote==nil{st:="failed: "+lastErr.Error(); if len(st)>80{st=st[:80]}; addLog(cip,target,lastIP,st,time.Since(start)); if isSocks{client.Write([]byte{5,4,0,1,0,0,0,0,0,0})}else{client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))}; atomic.AddInt64(&stats.FailedConns,1); return}; defer remote.Close(); atomic.AddInt64(&stats.SuccessConns,1); addLog(cip,target,lastIP,"成功",time.Since(start)); if isSocks{client.Write([]byte{5,0,0,1,0,0,0,0,0,0})}else{client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))}; deadline:=start.Add(1000*time.Second); var wg sync.WaitGroup; wg.Add(2); go copyConn(remote,client,deadline,&stats.TotalBytesSent,&wg); go copyConn(client,remote,deadline,&stats.TotalBytesRecv,&wg); wg.Wait() }
func handleSocks(c net.Conn,first byte,listenPort string){ defer c.Close(); defer atomic.AddInt64(&stats.ActiveConns,-1); b:=make([]byte,512); b[0]=first; if _,e:=io.ReadFull(c,b[1:2]); e!=nil{return}; n:=int(b[1]); if _,e:=io.ReadFull(c,b[:n]); e!=nil{return}; has:=false; for i:=0;i<n;i++{if b[i]==2{has=true}}; if !has{c.Write([]byte{5,255}); return}; c.Write([]byte{5,2}); if _,e:=io.ReadFull(c,b[:2]); e!=nil{return}; ulen:=int(b[1]); if _,e:=io.ReadFull(c,b[:ulen]); e!=nil{return}; u:=string(b[:ulen]); if _,e:=io.ReadFull(c,b[:1]); e!=nil{return}; plen:=int(b[0]); if _,e:=io.ReadFull(c,b[:plen]); e!=nil{return}; p:=string(b[:plen]); if !auth(listenPort,u,p){c.Write([]byte{1,1}); return}; c.Write([]byte{1,0}); if _,e:=io.ReadFull(c,b[:4]); e!=nil{return}; var host string; var port uint16; switch b[3]{case 1: if _,e:=io.ReadFull(c,b[:6]);e!=nil{return}; host=fmt.Sprintf("%d.%d.%d.%d",b[0],b[1],b[2],b[3]); port=binary.BigEndian.Uint16(b[4:6]); case 3: if _,e:=io.ReadFull(c,b[:1]);e!=nil{return}; l:=int(b[0]); if _,e:=io.ReadFull(c,b[:l+2]);e!=nil{return}; host=string(b[:l]); port=binary.BigEndian.Uint16(b[l:l+2]); case 4: if _,e:=io.ReadFull(c,b[:18]);e!=nil{return}; host=net.IP(b[:16]).String(); port=binary.BigEndian.Uint16(b[16:18]); default: c.Write([]byte{5,8,0,1,0,0,0,0,0,0}); return}; proxy(c,host,port,true) }
func handleHTTP(c net.Conn,first byte,listenPort string){ defer c.Close(); defer atomic.AddInt64(&stats.ActiveConns,-1); b:=make([]byte,8192); b[0]=first; n,e:=c.Read(b[1:]); if e!=nil{return}; lines:=strings.Split(string(b[:n+1]),"\r\n"); parts:=strings.Fields(lines[0]); if len(parts)<3{return}; ok:=false; for _,line:=range lines{ if strings.HasPrefix(strings.ToLower(line),"proxy-authorization: basic "){dec,e:=base64.StdEncoding.DecodeString(strings.TrimSpace(line[27:])); if e==nil{kv:=strings.SplitN(string(dec),":",2); if len(kv)==2&&auth(listenPort,kv[0],kv[1]){ok=true}} } }; if !ok{c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n")); return}; if parts[0]!="CONNECT"{c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n")); return}; h,ps,e:=net.SplitHostPort(parts[1]); if e!=nil&&strings.Count(parts[1],":")==1{sp:=strings.SplitN(parts[1],":",2); h=sp[0]; ps=sp[1]}; pn,e:=strconv.Atoi(ps); if e!=nil||pn<1||pn>65535{c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")); return}; proxy(c,h,uint16(pn),false) }
GOEOF
cat <<'GOEOF' >> main.go
func handleConn(c net.Conn,port string){ atomic.AddInt64(&stats.ActiveConns,1); atomic.AddInt64(&stats.TotalConns,1); one:=[]byte{0}; c.SetReadDeadline(time.Now().Add(10*time.Second)); n,e:=c.Read(one); c.SetReadDeadline(time.Time{}); if e!=nil||n!=1{c.Close(); atomic.AddInt64(&stats.ActiveConns,-1); return}; if one[0]==5{handleSocks(c,one[0],port)}else{handleHTTP(c,one[0],port)} }
func listen(ctx context.Context,port string,wg *sync.WaitGroup)(net.Listener,error){ l,e:=net.Listen("tcp",":"+port); if e!=nil{return nil,e}; wg.Add(1); go func(){defer wg.Done(); go func(){<-ctx.Done(); l.Close()}(); for{c,e:=l.Accept(); if e!=nil{select{case<-ctx.Done():return;default:continue}}; go handleConn(c,port)}}(); log.Printf("代理端口 %s 已监听，支持 HTTP 和 SOCKS5",port); return l,nil }
func discard(ctx context.Context){for{select{case<-ctx.Done():return; case ip:=<-discardQueue: removePoolIP(ip)}}}
func index(w http.ResponseWriter,r *http.Request){b,e:=os.ReadFile(indexHTMLPath); if e!=nil{http.Error(w,"index.html not found",500);return}; w.Header().Set("Content-Type","text/html; charset=utf-8"); w.Write(b)}
func webAuth(next http.HandlerFunc)http.HandlerFunc{return func(w http.ResponseWriter,r *http.Request){u,p,ok:=r.BasicAuth(); if !ok||u!=config.WebUsername||p!=config.WebPassword{w.Header().Set("WWW-Authenticate","Basic"); w.WriteHeader(401); return}; next(w,r)}}
func js(w http.ResponseWriter,v interface{}){w.Header().Set("Content-Type","application/json"); json.NewEncoder(w).Encode(v)}
func startWeb(ctx context.Context)*http.Server{mux:=http.NewServeMux(); mux.HandleFunc("/",webAuth(index)); mux.HandleFunc("/api/stats",webAuth(func(w http.ResponseWriter,r *http.Request){up:=time.Since(stats.StartTime); js(w,map[string]interface{}{"active":atomic.LoadInt64(&stats.ActiveConns),"total":atomic.LoadInt64(&stats.TotalConns),"success":atomic.LoadInt64(&stats.SuccessConns),"failed":atomic.LoadInt64(&stats.FailedConns),"pool":atomic.LoadInt64(&stats.PoolSize),"target":config.TargetPool,"bytes_recv":atomic.LoadInt64(&stats.TotalBytesRecv),"bytes_sent":atomic.LoadInt64(&stats.TotalBytesSent),"auto_rotate":config.AutoRotate,"rotate_interval":config.AutoRotateHours,"uptime":fmt.Sprintf("%dd %dh %dm",int(up.Hours())/24,int(up.Hours())%24,int(up.Minutes())%60)})})); mux.HandleFunc("/api/rotate",webAuth(func(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{http.Error(w,"只支持 POST",405);return}; go rotatePool(); js(w,map[string]string{"message":"轮换已开始"})})); mux.HandleFunc("/api/add_ips",webAuth(func(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{http.Error(w,"只支持 POST",405);return}; var q struct{Count int `json:"count"`}; _=json.NewDecoder(r.Body).Decode(&q); if q.Count<1{q.Count=1}; added:=addPoolIPs(q.Count); js(w,map[string]interface{}{"message":"新增完成","added":added,"pool":atomic.LoadInt64(&stats.PoolSize),"target":config.TargetPool})})); mux.HandleFunc("/api/pool",webAuth(func(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{http.Error(w,"只支持 POST",405);return}; var q struct{Count int `json:"count"`}; _=json.NewDecoder(r.Body).Decode(&q); if q.Count<1{http.Error(w,"count 必须大于 0",400);return}; pool:=setPoolTarget(q.Count); js(w,map[string]interface{}{"message":"数量已更新","pool":pool,"target":config.TargetPool})})); mux.HandleFunc("/api/clear_ips",webAuth(func(w http.ResponseWriter,r *http.Request){if r.Method!="POST"{http.Error(w,"只支持 POST",405);return}; deleted:=clearAllIPv6(); js(w,map[string]interface{}{"message":"IPv6 已全部删除","deleted":deleted,"pool":atomic.LoadInt64(&stats.PoolSize),"target":config.TargetPool})})); mux.HandleFunc("/api/logs",webAuth(func(w http.ResponseWriter,r *http.Request){logsLock.RLock(); x:=append([]*ConnLog(nil),logs...); logsLock.RUnlock(); if len(x)>10{x=x[len(x)-10:]}; js(w,x)})); mux.HandleFunc("/api/active",webAuth(func(w http.ResponseWriter,r *http.Request){activeLock.RLock(); arr:=[]*ActiveConn{}; for _,v:=range active{if len(arr)>=10{break}; c:=*v; c.Duration=fmt.Sprintf("%.1fs",time.Since(v.StartTime).Seconds()); arr=append(arr,&c)}; activeLock.RUnlock(); js(w,arr)})); srv:=&http.Server{Addr:":"+config.WebPort,Handler:mux}; go func(){if e:=srv.ListenAndServe(); e!=nil&&e!=http.ErrServerClosed{log.Printf("Web 服务失败: %v",e)}}(); log.Printf("Web 面板: http://0.0.0.0:%s",config.WebPort); return srv}
func cleanupPool(){poolLock.RLock(); arr:=append([]net.IP(nil),ipv6Pool...); poolLock.RUnlock(); for _,ip:=range arr{delIP(ip)}}
func main(){stats.StartTime=time.Now(); exe,e:=os.Executable(); if e!=nil{log.Fatalf("无法获取路径: %v",e)}; dir:=filepath.Dir(exe); configFilePath=filepath.Join(dir,"config.json"); indexHTMLPath=filepath.Join(dir,"index.html"); if _,e:=os.Stat(configFilePath); e!=nil{log.Println("未找到配置文件，开始首次配置"); if e:=firstSetup(); e!=nil{log.Fatalf("配置失败: %v",e)}; log.Println("配置已保存，安装脚本将继续启动服务"); return}; if e:=loadConfig(); e!=nil{log.Fatalf("加载配置失败: %v",e)}; prefixIP,prefixNet,e=net.ParseCIDR(config.IPv6Prefix); if e!=nil{log.Fatalf("无法解析 IPv6 前缀: %v",e)}; iface,e=netlink.LinkByName(config.Interface); if e!=nil{log.Fatalf("无法找到网卡: %v",e)}; if config.NextHopAddr!=""{nh:=net.ParseIP(config.NextHopAddr); if nh==nil{log.Fatalf("无效的下一跳地址: %s",config.NextHopAddr)}; a:=&netlink.Addr{IPNet:&net.IPNet{IP:nh,Mask:net.CIDRMask(64,128)},Flags:syscall.IFA_F_NODAD}; if e:=netlink.AddrAdd(iface,a); e!=nil&&!strings.Contains(e.Error(),"file exists"){log.Printf("添加下一跳地址失败: %v",e)}}; log.Printf("IPv6 代理 v7.6"); log.Printf("配置: 代理端口 %s, Web 端口 %s",config.Port,config.WebPort); log.Printf("网络: %s @ %s",config.IPv6Prefix,config.Interface); cleanupStale(); if e:=initPool(); e!=nil{log.Fatalf("初始化失败: %v",e)}; ctx,cancel:=context.WithCancel(context.Background()); discardQueue=make(chan net.IP,5000); go discard(ctx); go backgroundFill(ctx); go autoRotate(ctx); web:=startWeb(ctx); var wg sync.WaitGroup; listeners:=[]net.Listener{}; l,e:=listen(ctx,config.Port,&wg); if e!=nil{log.Fatalf("监听主端口失败: %v",e)}; listeners=append(listeners,l); for _,p:=range config.Ports{if p.Enabled&&p.Port!=""&&p.Port!=config.Port{if l,e:=listen(ctx,p.Port,&wg); e==nil{listeners=append(listeners,l)}else{log.Printf("端口 %s 监听失败: %v",p.Port,e)}}}; log.Println("服务就绪"); stop:=make(chan os.Signal,1); signal.Notify(stop,syscall.SIGINT,syscall.SIGTERM); <-stop; log.Println("正在关闭"); cancel(); web.Shutdown(context.Background()); for _,l:=range listeners{l.Close()}; wg.Wait(); cleanupPool(); log.Println("已关闭")}
GOEOF

cat <<'HTMLEOF' > index.html
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IPv6 代理面板</title>
<style>
body{background:#111827;color:#e5e7eb;font-family:Arial,"Microsoft YaHei",sans-serif;margin:0}.wrap{max-width:1180px;margin:auto;padding:24px}h1{font-size:24px;margin:0 0 18px}h2{font-size:17px;margin:0 0 12px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card,.box{background:#182132;border:1px solid #374151;border-radius:8px;padding:16px;margin-bottom:16px}.num{font-size:28px;color:#38bdf8;font-weight:bold;line-height:1.2}.muted{color:#9ca3af}.hint{font-size:12px;color:#9ca3af;font-weight:400}.controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;align-items:end}.field{display:flex;gap:8px;align-items:center}.field label{min-width:72px;color:#cbd5e1;font-size:14px}input{width:100%;box-sizing:border-box;background:#0f172a;border:1px solid #4b5563;color:#f8fafc;border-radius:6px;padding:10px;font-size:15px}button{border:0;border-radius:6px;padding:10px 12px;color:#0f172a;font-weight:700;cursor:pointer;white-space:nowrap}button:hover{filter:brightness(1.08)}.primary{background:#38bdf8}.ok{background:#34d399}.warn{background:#fbbf24}.danger{background:#fb7185}.status{min-height:20px;color:#cbd5e1;font-size:13px;margin-top:8px}table{width:100%;border-collapse:collapse;table-layout:auto}td,th{border-bottom:1px solid #334155;padding:8px;text-align:left;font-size:13px;word-break:break-all}th{color:#cbd5e1}@media(max-width:640px){.wrap{padding:14px}.field{align-items:stretch;flex-direction:column}.field label{min-width:0}.num{font-size:24px}}
</style>
</head>
<body>
<div class="wrap">
<h1>IPv6 代理运行监控</h1>
<div class="grid">
<div class="card"><div class="muted">活跃</div><div id="active" class="num">-</div></div>
<div class="card"><div class="muted">总连接</div><div id="total" class="num">-</div></div>
<div class="card"><div class="muted">成功</div><div id="success" class="num">-</div></div>
<div class="card"><div class="muted">失败</div><div id="failed" class="num">-</div></div>
<div class="card"><div class="muted">IP 池</div><div id="pool" class="num">-</div></div>
<div class="card"><div class="muted">目标数量</div><div id="target" class="num">-</div></div>
<div class="card"><div class="muted">总流量</div><div id="traffic" class="num" style="font-size:20px">-</div></div>
<div class="card"><div class="muted">运行时间</div><div id="uptime" class="num" style="font-size:18px">-</div></div>
</div>
<div class="box">
<h2>IP 池控制</h2>
<div class="controls">
<div class="field"><label for="addCount">增加 IPv6</label><input id="addCount" type="number" min="1" step="1" value="1"><button class="ok" onclick="addIps()">增加</button></div>
<div class="field"><label for="poolCount">IP 数量</label><input id="poolCount" type="number" min="1" step="1" value="1"><button class="primary" onclick="setPool()">修改</button></div>
<div class="field"><label>轮换</label><button class="warn" onclick="rotateNow()">立即轮换</button></div>
<div class="field"><label>清空</label><button class="danger" onclick="clearIps()">删除全部 IPv6</button></div>
</div>
<div id="opStatus" class="status"></div>
</div>
<div class="box"><h2>实时连接 <span class="hint">最多显示 10 条，超过 1000 秒自动断开</span></h2><table><thead><tr><th>客户端</th><th>目标</th><th>IPv6</th><th>时长</th></tr></thead><tbody id="act"></tbody></table></div>
<div class="box"><h2>最近日志 <span class="hint">仅保留 10 条</span></h2><table><thead><tr><th>时间</th><th>客户端</th><th>目标</th><th>IPv6</th><th>状态</th><th>耗时</th></tr></thead><tbody id="logs"></tbody></table></div>
</div>
<script>
async function j(u,o){let r=await fetch(u,o);if(!r.ok)throw new Error(await r.text());return r.json()}
function fmt(n){n=Number(n||0);let u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return (i?n.toFixed(2):n.toFixed(0))+' '+u[i]}
function rows(id,a,c){a=(a||[]).slice(-10);document.getElementById(id).innerHTML=a.length?a.map(x=>'<tr>'+c.map(f=>'<td>'+(f(x)||'')+'</td>').join('')+'</tr>').join(''):'<tr><td colspan="6" class="muted">暂无</td></tr>'}
function post(u,d){return j(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d||{})})}
function val(id){return Math.max(1,parseInt(document.getElementById(id).value||'1',10))}
function status(t){document.getElementById('opStatus').textContent=t}
async function addIps(){try{let r=await post('/api/add_ips',{count:val('addCount')});status('已新增 '+r.added+' 个 IPv6，目标数量 '+r.target);tick()}catch(e){status('操作失败: '+e.message)}}
async function setPool(){try{let r=await post('/api/pool',{count:val('poolCount')});status('IP 数量已修改为 '+r.target+'，当前池 '+r.pool);tick()}catch(e){status('操作失败: '+e.message)}}
async function rotateNow(){try{let r=await post('/api/rotate',{});status(r.message||'轮换已开始');setTimeout(tick,1500)}catch(e){status('操作失败: '+e.message)}}
async function clearIps(){if(!confirm('确定删除全部 IPv6 地址吗？'))return;try{let r=await post('/api/clear_ips',{});status('已删除 '+r.deleted+' 个 IPv6，目标数量已设为 '+r.target);tick()}catch(e){status('操作失败: '+e.message)}}
async function tick(){try{let s=await j('/api/stats');for(let k of ['active','total','success','failed','pool','target','uptime'])document.getElementById(k).textContent=s[k];if(document.activeElement.id!='poolCount')document.getElementById('poolCount').value=(s.target??s.pool??1);let sent=s.bytes_sent||0,recv=s.bytes_recv||0;document.getElementById('traffic').textContent=fmt(sent+recv);rows('act',await j('/api/active'),[x=>x.ClientIP||x.client_ip,x=>x.Target||x.target,x=>x.IPv6||x.ipv6,x=>x.Duration||x.duration]);rows('logs',await j('/api/logs'),[x=>x.Time||x.time,x=>x.ClientIP||x.client_ip,x=>x.Target||x.target,x=>x.IPv6||x.ipv6,x=>x.Status||x.status,x=>x.Duration||x.duration])}catch(e){}}
setInterval(tick,3000);tick()
</script>
</body>
</html>
HTMLEOF

print_success "源码创建完成"

print_info "编译程序"
if ping -c 1 -W 1 goproxy.cn >/dev/null 2>&1; then export GOPROXY=https://goproxy.cn,direct; fi
/usr/local/go/bin/go mod init ipv6-proxy >/dev/null 2>&1
/usr/local/go/bin/go mod tidy || { print_error "下载依赖失败"; exit 1; }
CGO_ENABLED=0 /usr/local/go/bin/go build -ldflags "-s -w" -o ipv6-proxy . || { print_error "编译失败"; exit 1; }

mkdir -p "$INSTALL_DIR"
mv ipv6-proxy index.html "$INSTALL_DIR/"
cd / && rm -rf "$BUILD_DIR"
print_success "安装完成"

cat >/etc/systemd/system/ipv6-proxy.service <<SERVICEEOF
[Unit]
Description=IPv6 Proxy v7.6
After=network-online.target
[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/ipv6-proxy
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
Restart=always
RestartSec=3
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
SERVICEEOF
systemctl daemon-reload

print_info "系统优化"
sysctl -w net.ipv6.neigh.default.gc_thresh1=2048 >/dev/null 2>&1 || true
sysctl -w net.ipv6.neigh.default.gc_thresh2=4096 >/dev/null 2>&1 || true
sysctl -w net.ipv6.neigh.default.gc_thresh3=10000 >/dev/null 2>&1 || true
sysctl -w net.core.somaxconn=8192 >/dev/null 2>&1 || true
ulimit -n 65535 2>/dev/null || true

cd "$INSTALL_DIR" || exit 1
if [ ! -f config.json ]; then ./ipv6-proxy || exit 1; fi
PROXY_PORT=$(grep -oP '"port"\s*:\s*"\K[^"]+' config.json 2>/dev/null || echo 1080)
WEB_PORT=$(grep -oP '"web_port"\s*:\s*"\K[^"]+' config.json 2>/dev/null || echo 8080)
if command -v ufw >/dev/null 2>&1; then ufw allow ${PROXY_PORT}/tcp >/dev/null 2>&1 || true; ufw allow ${WEB_PORT}/tcp >/dev/null 2>&1 || true; fi
systemctl enable ipv6-proxy >/dev/null 2>&1
systemctl restart ipv6-proxy
if systemctl is-active --quiet ipv6-proxy; then
  print_success "服务启动成功"
  print_info "默认会初始化 1 个 IPv6，Web 面板通常很快就绪"
  if wait_web_port "$WEB_PORT" 180; then
    print_success "Web 面板端口 ${WEB_PORT} 正常"
  else
    print_warning "服务已启动，但 Web 面板端口 ${WEB_PORT} 未响应"
    echo "请检查日志: journalctl -u ipv6-proxy -n 80 --no-pager"
    echo "请检查监听: ss -lntp | grep ${WEB_PORT}"
  fi
else
  print_warning "服务可能启动失败，请查看 systemctl status ipv6-proxy"
  echo "请检查日志: journalctl -u ipv6-proxy -n 80 --no-pager"
fi
IP=$(curl -s ifconfig.me 2>/dev/null || echo "你的服务器IP")
echo "Web 面板: http://${IP}:${WEB_PORT}"
echo "HTTP 代理: http://proxy:proxy@${IP}:${PROXY_PORT}"
echo "SOCKS5 代理: socks5://proxy:proxy@${IP}:${PROXY_PORT}"
echo "配置文件: $INSTALL_DIR/config.json"
