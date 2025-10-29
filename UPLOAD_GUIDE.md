# 🚀 GitHub 上传指南

## 方法一：通过 GitHub 网页界面（最简单）

### 步骤 1：创建新仓库
1. 访问 https://github.com/new
2. 填写：
   - **Repository name**: `ipv6-rotating-proxy`
   - **Description**: `🔄 One-click IPv6 rotating proxy server with SOCKS5/HTTP support`
   - 选择 **Public**（公开）
   - **不要**勾选 "Initialize with README"（我们已有 README）
3. 点击 **Create repository**

### 步骤 2：上传文件
1. 在新创建的仓库页面，点击 **uploading an existing file**
2. 拖拽或选择这 5 个文件：
   - `README.md`
   - `LICENSE`
   - `.gitignore`
   - `CONTRIBUTING.md`
   - `install.sh`
3. 在底部 Commit 信息填写：`Initial commit: IPv6 rotating proxy`
4. 点击 **Commit changes**

### 步骤 3：完成！
仓库地址将是：`https://github.com/YOUR_USERNAME/ipv6-rotating-proxy`

---

## 方法二：通过 Git 命令行

### 步骤 1：创建仓库
在 GitHub 网站创建新仓库（同上），然后：

```bash
# 进入文件目录
cd ipv6-proxy-github

# 初始化 Git
git init

# 添加所有文件
git add .

# 提交
git commit -m "Initial commit: IPv6 rotating proxy server"

# 添加远程仓库（替换 YOUR_USERNAME）
git remote add origin https://github.com/YOUR_USERNAME/ipv6-rotating-proxy.git

# 推送到 GitHub
git branch -M main
git push -u origin main
```

---

## 📝 上传后需要做的

### 1. 更新 README 中的链接
将 README.md 中的所有 `YOUR_USERNAME` 替换为你的 GitHub 用户名：
- `https://github.com/YOUR_USERNAME/ipv6-rotating-proxy`

### 2. 添加 Topics（标签）
在仓库页面点击 ⚙️ Settings → 在 About 区域添加 topics：
- `ipv6`
- `proxy`
- `socks5`
- `http-proxy`
- `golang`
- `proxy-server`
- `rotating-proxy`

### 3. 编辑 LICENSE
将 LICENSE 文件中的 `[Your Name]` 改为你的名字

### 4. 测试安装链接
确认这个命令能正常工作：
```bash
wget -O install.sh https://raw.githubusercontent.com/YOUR_USERNAME/ipv6-rotating-proxy/main/install.sh
```

---

## 🎯 推广你的项目

### 添加徽章（Badges）
在 README.md 顶部添加：
```markdown
![License](https://img.shields.io/github/license/YOUR_USERNAME/ipv6-rotating-proxy)
![Stars](https://img.shields.io/github/stars/YOUR_USERNAME/ipv6-rotating-proxy)
![Issues](https://img.shields.io/github/issues/YOUR_USERNAME/ipv6-rotating-proxy)
```

### 在社交媒体分享
- Twitter
- Reddit (r/golang, r/selfhosted)
- Hacker News
- V2EX

---

## 📦 文件清单

确保你有这些文件：
- ✅ `README.md` - 项目文档（中英文）
- ✅ `LICENSE` - MIT 许可证
- ✅ `.gitignore` - Git 忽略规则
- ✅ `CONTRIBUTING.md` - 贡献指南
- ✅ `install.sh` - 安装脚本

---

## 🔒 安全提醒

上传到 GitHub 前请确认：
- ❌ 没有包含任何密码或密钥
- ❌ 没有包含 IP 地址或服务器信息
- ✅ 所有敏感信息都在 .gitignore 中

---

## 需要帮助？

如果遇到问题：
1. 检查文件是否都已下载
2. 确认 GitHub 账号已登录
3. 如果上传失败，尝试刷新页面重试

祝你的项目获得很多 ⭐ Star！
