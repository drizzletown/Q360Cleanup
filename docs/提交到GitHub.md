# Q360 Cleanup v1.0.0 — GitHub 发布步骤

## 1. 上传源码

在 GitHub 新建 **空仓库**，建议名称 `Q360Cleanup`（不要预创建 README 或 LICENSE）。解压 `Q360Cleanup-v1.0.0-GitHub-Source.zip`，在根目录打开 PowerShell：

```powershell
git init
git add .
git commit -m "Release candidate v1.0.0"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/Q360Cleanup.git
git push -u origin main
```

替换 `YOUR_USERNAME`。仓库中 **不**提交二进制、真实机器日志、系统配置或隔离数据。

## 2. 确认 CI

访问仓库 **Actions → CI - Core tests and Windows native validation**，核对 `linux-core` 和 `windows-native` 两个作业，必须全部绿色。Windows native 作业会执行只读集成测试；它不会安装或卸载 360 软件。

## 3. 建立正式标签

```powershell
git tag -a v1.0.0 -m "Q360 Cleanup v1.0.0 release candidate"
git push origin v1.0.0
```

注意标签仅表示版本号，不等于真实 Windows/360 验收通过。

## 4. 准备 Release 草稿

在 **Actions → Draft GitHub Release (requires manual review) → Run workflow** 中输入 `v1.0.0`。工作流从标签源码执行 Windows 原生测试、构建 EXE、验证哈希、压缩资产，并创建一个标注 **Draft / Pre-release** 的 Release。需要仓库允许该工作流使用 `contents: write` 权限创建 Release。

打开 **Releases → Drafts**，核对 `Q360Cleanup-v1.0.0-windows-x64-unsigned.zip` 和 `docs/RELEASE_NOTES_v1.0.0.md` 的限制说明。也可以手动上传本地完整 Windows ZIP。

### 严禁提前宣称 Stable

要把草稿真正设为正式稳定 Release，需先完成 `docs/RELEASE_CHECKLIST.md` 中 C 类所有 Windows/360 实机验收和代码签名评估，并记录在 `docs/REAL_WORLD_VALIDATION.md`。否则公开展示请保留 **Pre-release** 标签。
