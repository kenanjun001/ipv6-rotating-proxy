#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

clear
echo "========================================="
echo "  IPv6 轮换检测测试"
echo "========================================="
echo ""

PROXY="http://proxy:proxy@127.0.0.1:20000"

# 测试多个网站
SITES=(
    "https://api.ip.sb/ip"
    "https://ifconfig.me"
    "https://ipinfo.io/ip"
    "https://icanhazip.com"
    "http://ip.sb"
)

echo "🔍 第一步：找一个可用的检测网站..."
echo ""

WORKING_SITE=""
for site in "${SITES[@]}"; do
    echo -n "  测试 $site ... "
    RESULT=$(curl -x $PROXY -s --max-time 10 "$site" 2>&1 | head -1)
    if [ ! -z "$RESULT" ] && [ ${#RESULT} -lt 100 ]; then
        echo -e "${GREEN}✓ 可用${NC}"
        echo "    返回: $RESULT"
        WORKING_SITE="$site"
        break
    else
        echo -e "${RED}✗ 不可用${NC}"
    fi
done

if [ -z "$WORKING_SITE" ]; then
    echo ""
    echo -e "${RED}[错误]${NC} 所有测试网站都不可用"
    echo ""
    echo "请检查："
    echo "  1. 代理是否正常运行: systemctl status ipv6-proxy"
    echo "  2. 网络连接是否正常"
    echo "  3. 查看日志: journalctl -u ipv6-proxy -n 50"
    exit 1
fi

echo ""
echo "========================================="
echo "  使用 $WORKING_SITE 进行测试"
echo "========================================="
echo ""

# 获取初始统计
INITIAL_METRICS=$(curl -s http://127.0.0.1:20001/metrics)
INITIAL_TOTAL=$(echo "$INITIAL_METRICS" | grep "proxy_total" | awk '{print $2}')
INITIAL_IPV6_ACTIVE=$(echo "$INITIAL_METRICS" | grep "ipv6_active" | awk '{print $2}')

echo "📊 初始状态:"
echo "  总连接数: $INITIAL_TOTAL"
echo "  活跃IPv6: $INITIAL_IPV6_ACTIVE"
echo ""

# IPv6轮换测试
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎲 IPv6 轮换测试 (连续15次请求)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

declare -A ip_map
unique_count=0
success_count=0
fail_count=0

for i in {1..15}; do
    echo -n "请求 $i: "
    
    # 获取IP地址
    IP=$(curl -x $PROXY -s --max-time 15 "$WORKING_SITE" 2>&1 | head -1 | tr -d '\r\n' | grep -E '^[0-9a-f:]+$|^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    
    if [ ! -z "$IP" ] && [ ${#IP} -lt 100 ]; then
        success_count=$((success_count + 1))
        
        # 检查是否是新IP
        if [ -z "${ip_map[$IP]}" ]; then
            ip_map[$IP]=1
            unique_count=$((unique_count + 1))
            echo -e "${GREEN}$IP ⭐ (新IP #${unique_count})${NC}"
        else
            ip_map[$IP]=$((${ip_map[$IP]} + 1))
            echo -e "${YELLOW}$IP (第 ${ip_map[$IP]} 次)${NC}"
        fi
    else
        fail_count=$((fail_count + 1))
        echo -e "${RED}失败${NC}"
    fi
    
    # 短暂延迟，避免太快
    sleep 0.3
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 测试结果统计"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "总请求数: 15"
echo "  成功: $success_count"
echo "  失败: $fail_count"
echo "  使用的不同IP: $unique_count"
echo ""

if [ $unique_count -gt 0 ]; then
    echo "🔍 IP使用详情:"
    for ip in "${!ip_map[@]}"; do
        count=${ip_map[$ip]}
        echo "  $ip - 使用了 $count 次"
    done
    echo ""
fi

# 计算轮换率
if [ $success_count -gt 0 ]; then
    ROTATION_RATE=$(echo "scale=1; $unique_count * 100 / $success_count" | bc 2>/dev/null || echo "N/A")
    echo "📈 IP轮换率: ${ROTATION_RATE}% (${unique_count}/${success_count})"
    echo ""
fi

# 获取最终统计
FINAL_METRICS=$(curl -s http://127.0.0.1:20001/metrics)
FINAL_TOTAL=$(echo "$FINAL_METRICS" | grep "proxy_total" | awk '{print $2}')
FINAL_IPV6_ACTIVE=$(echo "$FINAL_METRICS" | grep "ipv6_active" | awk '{print $2}')

TOTAL_DIFF=$((FINAL_TOTAL - INITIAL_TOTAL))

echo "📊 代理统计变化:"
echo "  新增连接: $TOTAL_DIFF"
echo "  当前活跃IPv6: $FINAL_IPV6_ACTIVE"
echo ""

# 评估结果
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 评估"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ $unique_count -ge 12 ]; then
    echo -e "${GREEN}✅ 优秀！${NC} 每次请求几乎都使用不同的IPv6"
    echo "   轮换率: ${ROTATION_RATE}%"
elif [ $unique_count -ge 8 ]; then
    echo -e "${GREEN}✅ 良好！${NC} IPv6轮换正常"
    echo "   轮换率: ${ROTATION_RATE}%"
elif [ $unique_count -ge 5 ]; then
    echo -e "${YELLOW}⚠️  一般${NC} 有一定的IP复用"
    echo "   轮换率: ${ROTATION_RATE}%"
    echo "   可能原因: 随机碰撞或并发限制"
elif [ $unique_count -ge 2 ]; then
    echo -e "${YELLOW}⚠️  较差${NC} IP轮换较少"
    echo "   轮换率: ${ROTATION_RATE}%"
    echo "   建议检查配置"
else
    echo -e "${RED}❌ 失败${NC} IP基本没有轮换"
    echo "   可能原因:"
    echo "   - IPv6未正确启用"
    echo "   - 网络配置问题"
    echo "   - 查看日志: journalctl -u ipv6-proxy -n 50"
fi

echo ""
echo "========================================="
echo "  测试完成"
echo "========================================="
