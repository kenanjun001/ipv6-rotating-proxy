#!/bin/bash
set -e

echo "============================================="
echo "=== IPv6 代理 v8.0 安装测试版 ==="
echo "============================================="

if [ "$(id -u)" -ne 0 ]; then
  echo "❌ 需要 root 权限"
  exit 1
fi

echo "步骤 1: 清理..."
systemctl stop ipv6-proxy.service 2>/dev/null || echo "服务不存在，跳过"
killall -9 ipv6-proxy 2>/dev/null || echo "进程不存在，跳过"
rm -rf /opt/ipv6-proxy /root/ipv6-build
echo "✅ 清理完成"

echo "步骤 2: 创建目录..."
mkdir -p /root/ipv6-build
cd /root/ipv6-build
echo "✅ 目录创建完成"

echo "步骤 3: 检查 Go..."
export PATH=/usr/local/go/bin:$PATH
if ! command -v go &> /dev/null; then
    echo "需要安装 Go，开始下载..."
    apt-get update -qq
    apt-get install -y wget -qq
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    echo "✅ Go 安装完成"
else
    echo "✅ Go 已存在: $(go version)"
fi

echo ""
echo "============================================="
echo "测试完成！如果看到这行说明脚本可以正常运行。"
echo "============================================="
echo ""
echo "接下来需要下载完整版源代码包。"
echo "请告诉我测试结果！"
