package matcher

import (
	"regexp"
	"strings"
)

// Classify classifies consumer 360-family software conservatively.
// No program is uninstalled based on a substring or publisher alone.
type Decision struct {
	Match          bool
	HighConfidence bool
	Reason         string
}

var families = []string{
	"安全卫士", "杀毒", "安全浏览器", "极速浏览器", "ai浏览器", "压缩",
	"壁纸", "桌面助手", "桌面整理", "驱动大师", "软件管家", "软件小助手",
	"看图", "pdf", "手机助手", "游戏大厅", "游戏管家", "画报",
	"安全云盘", "安全云", "清理大师", "浏览器", "极速版", "safe", "total security",
	"zip", "security", "browser", "antivirus", "screen saver", "wallpaper",
}

var enterprise = []string{
	"企业版", "企业安全", "政企", "终端安全", "天擎", "天鉴", "edr", "endpoint",
	"enterprise", "business", "管理中心", "集中管理", "网管", "服务器版",
}

func Classify(name, publisher string) Decision {
	n := strings.ToLower(strings.TrimSpace(name))
	p := strings.ToLower(strings.TrimSpace(publisher))
	if n == "" {
		return Decision{}
	}
	for _, forbidden := range enterprise {
		if strings.Contains(n, forbidden) {
			return Decision{Reason: "企业/集中管理产品，排除自动卸载范围"}
		}
	}
	hasBrand := strings.HasPrefix(n, "360") || strings.HasPrefix(n, "奇虎360") ||
		strings.HasPrefix(n, "qihoo 360") || strings.HasPrefix(n, "360 ")
	if !hasBrand {
		return Decision{}
	}
	known := false
	for _, f := range families {
		if strings.Contains(n, f) {
			known = true
			break
		}
	}
	publisherOK := false
	for _, v := range []string{"奇虎", "三六零", "qihoo", "360 security", "360安全", "360.cn", "360 internet", "beijing qihu"} {
		if strings.Contains(p, v) {
			publisherOK = true
			break
		}
	}
	if known && publisherOK {
		return Decision{true, true, "产品名称和发布者均符合360消费级产品"}
	}
	if known {
		return Decision{true, false, "产品名称符合360消费级产品，发布者需人工确认"}
	}
	if publisherOK {
		return Decision{true, false, "360发布者，但非已知产品类型，请人工核对"}
	}
	return Decision{}
}

// IsMSI recognizes only a registered MSI product code or an actual msiexec
// command with exactly one product GUID and an /i or /x product operation.
// It does not treat GUIDs embedded in arbitrary command lines as MSI commands.
var guidPattern = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)
var guidAnywhere = regexp.MustCompile(`(?i)\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}`)

func MSIProductCode(registrySubkey, uninstallString string, windowsInstaller bool) string {
	subkey := strings.TrimSpace(registrySubkey)
	if windowsInstaller && guidPattern.MatchString(subkey) {
		return strings.ToUpper(subkey)
	}
	args := ParseWindowsCommandLine(strings.TrimSpace(uninstallString))
	if len(args) < 2 {
		return ""
	}
	command := strings.ToLower(strings.ReplaceAll(args[0], "/", `\`))
	validExe := command == "msiexec" || command == "msiexec.exe" ||
		strings.HasSuffix(command, `\windows\system32\msiexec.exe`) ||
		strings.HasSuffix(command, `\windows\syswow64\msiexec.exe`)
	if !validExe {
		return ""
	}
	all := guidAnywhere.FindAllString(uninstallString, -1)
	if len(all) != 1 {
		return ""
	}
	for i := 1; i < len(args); i++ {
		a := strings.ToLower(args[i])
		if a == "/x" || a == "-x" || a == "/i" || a == "-i" {
			if i+1 < len(args) && strings.EqualFold(args[i+1], all[0]) {
				return strings.ToUpper(all[0])
			}
		}
		if len(a) >= 3 && (strings.HasPrefix(a, "/x") || strings.HasPrefix(a, "-x") || strings.HasPrefix(a, "/i") || strings.HasPrefix(a, "-i")) &&
			strings.EqualFold(a[2:], all[0]) {
			return strings.ToUpper(all[0])
		}
	}
	return ""
}

// SafeUninstallerBase is intentionally conservative. A nearby unrelated file
// such as unsafe_setup.exe is not a valid registered vendor uninstall entry.
func SafeUninstallerBase(base string) bool {
	b := strings.ToLower(strings.TrimSpace(base))
	if !strings.HasSuffix(b, ".exe") {
		return false
	}
	for _, exact := range []string{"uninst.exe", "uninstall.exe", "unins000.exe", "unins001.exe", "unins002.exe", "setup.exe", "remove.exe", "360safe.exe", "360sd.exe"} {
		if b == exact {
			return true
		}
	}
	return strings.HasPrefix(b, "uninst") || strings.HasPrefix(b, "unins") || strings.HasPrefix(b, "uninstall")
}

// Plausible360Path requires a specific vendor directory segment. A substring
// "360" in a Windows folder, download filename or Autodesk path is not enough.
func Plausible360Path(p string) bool {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "/", `\`))
	segments := strings.Split(p, `\`)
	for _, seg := range segments[:max(0, len(segments)-1)] {
		switch {
		case seg == "360", seg == "qihoo 360", seg == "qihoo", seg == "qihu", seg == "奇虎360", seg == "三六零":
			return true
		case strings.HasPrefix(seg, "360safe"), strings.HasPrefix(seg, "360sd"), strings.HasPrefix(seg, "360se"), strings.HasPrefix(seg, "360chrome"), strings.HasPrefix(seg, "360zip"), strings.HasPrefix(seg, "360security"), strings.HasPrefix(seg, "360browser"), strings.HasPrefix(seg, "360wallpaper"):
			return true
		}
	}
	return false
}
