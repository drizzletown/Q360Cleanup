# Q360 Cleanup — 360 消费级软件卸载诊断与恢复工具

**v1.0.0 · Windows 10/11 x64 · MIT License · 源码可审计 · 无第三方 Go 依赖**

Q360 Cleanup 用于帮助**计算机所有者或经授权的管理员**梳理、卸载和核验 360 消费级软件。它优先使用可信且由系统登记的正规卸载入口；卸载失败时给出原因，不会通过强杀保护进程、停用防护、删除驱动或破坏系统 ACL 的方式强制移除。

> **发布状态：v1.0.0 构建已完成，Windows/360 实机验收未完成。** 可作为 GitHub 公开测试候选版本发布；在通过 [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) 前，请把 GitHub Release 保持为 **Draft/Pre-release**，不要宣称稳定版或“100% 彻底卸载”。本工具不是 360 官方产品，也不受其认可或支持。

## 功能

| 模块 | 功能和边界 |
| --- | --- |
| 产品发现 | HKCU/HKLM、32/64 位卸载项；以厂商与产品族综合识别，排除 Autodesk Fusion 360 等无关软件和企业托管产品 |
| 可信卸载 | MSI 通过 Windows Installer 核对实际产品名和发布者，EXE 检查所在目录、可执行名称和 Authenticode 签名；不调用任意 shell 卸载命令 |
| 故障诊断 | 区分 MSI 3010/1641/1602/1603/1618/1612 等返回状态；第三方 EXE 可能异步卸载，因此停止后续自动串行处理 |
| 残留审计 | 只读检查进程、服务及驱动登记、任务、启动项、已知目录和注册表线索；扫描错误会影响验收结论 |
| 可恢复隔离 | 仅在重新审计无后台组件时允许少量当前用户数据目录做精确白名单移动，支持隔离日志和安全恢复；拒绝覆盖、拒绝未授权路径 |
| 重启验收 | 记录逐产品状态与启动时间；只有重启后、会话完整、检查项均无发现才给出“范围内通过”，并非全系统无残留证明 |

## 获取和运行

发布资产见 GitHub Releases（**由仓库维护者上传/审核**），也可以下载此仓库源码自行构建。此程序为便携版：**没有 MSI 安装器**，也不需要安装常驻服务。

1. 在可回滚的 Windows 10/11 x64 测试机上解压 `Q360Cleanup-v1.0.0-windows-x64-unsigned.zip`。
2. 备份浏览器书签与重要文档，建议创建虚拟机快照。
3. 右键 `启动-管理员模式.cmd` 运行，允许 Windows UAC；或者自行对 EXE 选择“以管理员身份运行”。
4. 扫描安装项，人工确认产品名称、发布者和卸载入口；再逐项运行官方卸载向导。
5. 出现失败、重启提示或状态不确定时停止操作，保留日志；重启后重新深度诊断和验收。
6. 仅在已无目标产品、服务、驱动和自启动证据的前提下，才考虑用户数据目录隔离；如需恢复，在程序中操作，勿手工篡改隔离索引。

**提示：** 本程序尚未签名。Windows 可能出现“未知发布者”提醒。这不意味着可关闭 Defender/SmartScreen；如有疑虑，请从源码构建或停止使用。

## 构建和自测

要求 **Go 1.23+**。在项目根目录：

```powershell
./scripts/test-windows.ps1
```

该脚本执行不卸载任何第三方产品的 Windows 原生测试、`go vet`、构建与 SHA-256 校验。也可单独运行：

```powershell
cd source
go test -count=1 ./...
go vet ./...
cd ..
./scripts/build-windows.ps1
./scripts/verify-release.ps1
```

Windows x64 可执行文件输出到 `dist/Q360Cleanup_Windows_x64.exe`。Linux 只支持业务规则测试与 Windows 交叉编译，**不能用它替代 Windows 原生 UAC、NTFS、GUI 或真实卸载验收**。

## 隐私和安全

报告可能包含系统路径、程序版本及 Windows 用户信息，只保存在执行主机的 `%LOCALAPPDATA%\\Q360Cleanup`，不会由本程序上传。反馈问题时删除用户名、具体个人路径和其他敏感数据。另请阅读 [安全模型](docs/SECURITY_MODEL.md)、[安全漏洞报告](SECURITY.md) 和 [测试矩阵](docs/TEST_MATRIX.md)。

## 发布与项目维护

- [GitHub 提交流程](docs/提交到GitHub.md)
- [v1.0.0 发行说明](docs/RELEASE_NOTES_v1.0.0.md)
- [Windows 手工验收脚本](docs/WINDOWS_ACCEPTANCE.md)
- [发布检查单](docs/RELEASE_CHECKLIST.md)
- [变更记录](CHANGELOG.md)

欢迎提供有机器快照、可复现的合法卸载测试案例。未经机器所有者或管理员授权，请勿操作任何系统。项目与 360 公司无隶属、认可或合作关系。
