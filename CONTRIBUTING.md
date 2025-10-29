# Contributing to IPv6 Rotating Proxy

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/YOUR_USERNAME/ipv6-rotating-proxy/issues)
2. If not, create a new issue with:
   - Clear title
   - Detailed description
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Go version)
   - Relevant logs

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain why it would be useful

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- Follow Go best practices
- Add comments for complex logic
- Keep functions focused and small
- Use meaningful variable names

### Testing

Before submitting:
```bash
# Test the installation script
sudo ./install.sh

# Verify service starts
systemctl status ipv6-proxy

# Test proxy functionality
curl -x socks5://user:pass@localhost:20000 http://ipv6.ip.sb
```

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ipv6-rotating-proxy.git
cd ipv6-rotating-proxy

# Make changes
# Test changes

# Commit
git add .
git commit -m "Description of changes"
git push
```

## Questions?

Feel free to open an issue for any questions!

---

## 贡献指南（中文）

感谢您的贡献！🎉

### 报告 Bug

1. 先检查 [Issues](https://github.com/YOUR_USERNAME/ipv6-rotating-proxy/issues) 中是否已有相同问题
2. 如果没有，创建新 issue 并包含：
   - 清晰的标题
   - 详细描述
   - 重现步骤
   - 预期行为 vs 实际行为
   - 系统信息（操作系统、Go 版本）
   - 相关日志

### 功能建议

1. 创建带 `enhancement` 标签的 issue
2. 描述功能和使用场景
3. 说明为什么有用

### Pull Request 流程

1. Fork 仓库
2. 创建功能分支 (`git checkout -b feature/新功能`)
3. 进行修改
4. 充分测试
5. 提交清晰的 commit (`git commit -m '添加新功能'`)
6. 推送到你的 fork (`git push origin feature/新功能`)
7. 创建 Pull Request

### 代码风格

- 遵循 Go 最佳实践
- 为复杂逻辑添加注释
- 保持函数简洁专注
- 使用有意义的变量名

### 测试

提交前请测试：
```bash
# 测试安装脚本
sudo ./install.sh

# 验证服务启动
systemctl status ipv6-proxy

# 测试代理功能
curl -x socks5://用户名:密码@localhost:20000 http://ipv6.ip.sb
```

## 有疑问？

随时创建 issue 提问！
