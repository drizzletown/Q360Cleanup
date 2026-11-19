package safecore

import (
	"fmt"
	"path/filepath"
	"strings"
)

// QuarantinableDir matches only exact, approved per-user / application-data
// directory names. Program Files, Windows, System32 and arbitrary paths are
// intentionally excluded from automatic directory moves.
func QuarantinableDir(path string, roots map[string]string) (string, bool) {
	allow := map[string][]string{
		"ProgramData":  {"360", "360Safe", "360Security", "Qihoo 360"},
		"LOCALAPPDATA": {"360", "360Chrome", "360se6", "360zip", "360Security", "Qihoo 360"},
		"APPDATA":      {"360", "360se6", "360Chrome", "Qihoo 360"},
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == "." {
		return "", false
	}
	for env, names := range allow {
		root := roots[env]
		if root == "" || !filepath.IsAbs(root) {
			continue
		}
		for _, name := range names {
			expected := filepath.Clean(filepath.Join(root, name))
			if strings.EqualFold(clean, expected) {
				return env + ":" + name, true
			}
		}
	}
	return "", false
}

// MSIResult never treats process exit as proof that the product is absent.
// These are diagnostic labels, not completion attestations.
func MSIResult(code int) (message string, needsReboot bool, accepted bool) {
	switch code {
	case 0:
		return "安装器返回 0；仍须验证安装登记和残留", false, true
	case 3010:
		return "安装器返回 3010：需要重启以完成卸载", true, true
	case 1641:
		return "安装器返回 1641：安装器已触发重启", true, true
	case 1602:
		return "安装器返回 1602：用户取消卸载", false, false
	case 1603:
		return "安装器返回 1603：卸载发生严重错误；检查权限、占用和安装器日志", false, false
	case 1618:
		return "安装器返回 1618：已有其他 MSI 安装任务在运行", false, false
	case 1605:
		return "安装器返回 1605：该 MSI 产品未安装/已被移除", false, false
	case 1612:
		return "安装器返回 1612：安装源不存在；可考虑官方修复安装", false, false
	default:
		return fmt.Sprintf("安装器返回 %d；含义待查，不可视为卸载成功", code), false, false
	}
}

type Evidence struct {
	SessionExists      bool
	RebootObserved     bool
	Installed          int
	Services           int
	Processes          int
	Tasks              int
	Startup            int
	Folders            int
	Registry           int
	QuarantinePending  int
	ScanError          bool
	WorkflowFailed     bool
	WorkflowIncomplete bool
}

type Verdict struct {
	Level   string
	Message string
}

// Verdict rules prioritize avoiding false assertions of success.
func Assess(e Evidence) Verdict {
	if !e.SessionExists {
		return Verdict{"未开始", "没有本工具记录的卸载会话；仅可生成当前系统清单"}
	}
	if e.ScanError {
		return Verdict{"无法判定", "部分系统项目读取失败；请提升权限后复查"}
	}
	if e.WorkflowFailed {
		return Verdict{"卸载失败", "至少一项卸载失败/受阻；本次会话不能判定为通过，请重新执行并记录成功结果"}
	}
	if e.WorkflowIncomplete {
		return Verdict{"卸载流程未完成", "目标尚有未尝试、执行中或尚待重启的卸载步骤；不能认定成功"}
	}
	if e.Installed > 0 {
		return Verdict{"未完成", "仍发现已登记的目标产品；需继续卸载或修复卸载器"}
	}
	if e.Services > 0 || e.Processes > 0 || e.Tasks > 0 || e.Startup > 0 {
		return Verdict{"需人工处置", "仍发现与 360 可能相关的服务/驱动、进程、计划任务或启动项；先确认归属，不能自动认定为可删除"}
	}
	if !e.RebootObserved {
		return Verdict{"等待重启", "目标产品登记已消失，但尚未观察到卸载后的系统重启"}
	}
	if e.Folders > 0 || e.Registry > 0 || e.QuarantinePending > 0 {
		return Verdict{"残留待确认", "尚有目录、注册表线索或隔离中的数据；请按归属和风险复核"}
	}
	return Verdict{"范围内通过", "本工具当前支持的检查范围未发现目标项；不等于对整个 Windows 的零残留保证"}
}

// TaskMatch intentionally demands a task name or vendor-specific filesystem
// segment in the XML text instead of accepting an arbitrary substring "360".
func TaskMatch(name, content string) bool {
	n := strings.ToLower(strings.ReplaceAll(name, "/", `\`))
	c := strings.ToLower(strings.ReplaceAll(content, "/", `\`))
	if strings.Contains(n, "qihoo") || strings.Contains(n, "奇虎") ||
		strings.Contains(n, "360safe") || strings.Contains(n, "360sd") ||
		strings.Contains(n, "360browser") || strings.Contains(n, "360zip") || strings.Contains(n, `\360\`) ||
		strings.HasPrefix(n, "360_") || strings.HasPrefix(n, "360-") {
		return true
	}
	for _, seg := range []string{`\360safe\`, `\360sd\`, `\360chrome\`, `\360se6\`, `\qihoo\`, `\qihoo 360\`, `\360zip\`} {
		if strings.Contains(c, seg) {
			return true
		}
	}
	return false
}
