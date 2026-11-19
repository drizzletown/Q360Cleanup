# Q360 Cleanup v1.0.0 — 本机测试记录

执行日期：2026-11-19。测试环境：Linux amd64、Go 1.23.2；Windows x64 为交叉编译。

| 检查 | 结果 |
| --- | --- |
| `go test -count=1 -coverprofile=... ./...` | PASS |
| Go 核心业务规则覆盖率 | **82.4%**（matcher 89.8%，safecore 79.6%；**不包含 Windows 专属实现**） |
| `go test -race -count=1 ./...` | PASS |
| `go vet ./...` | PASS |
| 连续 20 次 `go test -count=1 ./...` | PASS |
| `GOOS=windows GOARCH=amd64 go vet ./...` | PASS |
| Windows x64 GUI 交叉编译 | PASS |
| Windows 专属原生测试二进制交叉编译 | PASS（**未执行**） |
| 两次相同 Windows build 的二进制逐字节比较 | PASS |
| MSI 命令模糊测试 | PASS，187,160 次输入 |
| 产品识别模糊测试 | PASS，15,597 次输入 |
| GitHub Actions 工作流 YAML 语法解析 | PASS（没有在 GitHub 平台实际运行） |

**Windows EXE SHA-256**

`89790888f52ef30aadbe87e4b13a83aa2380abb7441a201712f97debe0abc914`

**未完成**：真实 Windows 10/11 GUI、UAC、Windows 原生测试实际运行、360 自保护卸载、NTFS 隔离恢复、代码签名和 Windows SmartScreen 评估。绝不能从上述 Linux 测试推断这些项目已通过。
