//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"q360cleanup/matcher"
	"q360cleanup/safecore"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var exePattern = regexp.MustCompile(`(?i)\.exe(?:"|\s|$)`)

func commandArgs(command string) ([]string, error) {
	command = strings.TrimSpace(expandWindows(command))
	if command == "" {
		return nil, errors.New("注册表未提供卸载命令")
	}
	result := matcher.ParseWindowsCommandLine(command)
	if len(result) == 0 || len(result) > 128 {
		return nil, errors.New("卸载命令无法解析")
	}
	if _, err := os.Stat(result[0]); err == nil {
		return result, nil
	}
	// Legacy uninstall registrations sometimes omit quotes around paths containing spaces.
	if m := exePattern.FindStringIndex(command); m != nil {
		candidate := strings.TrimSpace(strings.Trim(command[:m[0]+4], `"`))
		if strings.Contains(candidate, `:\`) {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				rest := strings.TrimSpace(command[m[1]:])
				args := matcher.ParseWindowsCommandLine(rest)
				return append([]string{candidate}, args...), nil
			}
		}
	}
	return result, nil
}

// absoluteUninstallExe refuses path traversal, junction/symlink redirects, temp
// locations, and unexpected executables. It does not assert Authenticode
// publisher identity; unsigned installer trust must be assessed by the user.
func absoluteUninstallExe(path string) (location string, err error) {
	path = filepath.Clean(strings.Trim(path, `"`))
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
		return "", errors.New("拒绝执行非本地绝对路径（含UNC网络位置）")
	}
	if !matcher.Plausible360Path(path) || !matcher.SafeUninstallerBase(filepath.Base(path)) {
		return "", errors.New("卸载程序名称或所属目录不符合高可信范围")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("卸载文件不存在或不可访问：%w", err)
	}
	if !strings.EqualFold(filepath.Clean(resolved), path) {
		return "", errors.New("卸载程序所在路径经过符号链接/联接点重定向")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("卸载程序不是可访问的普通文件")
	}
	roots := []struct {
		id    int
		label string
	}{
		{csidlProgramFiles, "系统应用目录"}, {csidlProgramFilesX86, "系统应用目录"},
		{csidlCommonAppData, "共享应用数据目录（须核实签名）"},
		{csidlLocalAppData, "用户应用目录（须核实签名）"},
	}
	for _, r := range roots {
		root, e := knownFolder(r.id)
		if e != nil {
			continue
		}
		rel, e := filepath.Rel(root, path)
		if e == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, `..\`) && !filepath.IsAbs(rel) {
			return r.label, nil
		}
	}
	return "", errors.New("拒绝从临时目录、下载目录、可移动盘或未知位置提权执行卸载程序；请改用 Windows 卸载界面")
}

// inspectUninstaller checks the registered command without starting a process.
func inspectUninstaller(a appEntry) string {
	if matcher.MSIProductCode(a.KeyName, a.Uninstall, a.Msi) != "" {
		return "MSI入口"
	}
	if strings.TrimSpace(a.Uninstall) == "" {
		return "卸载入口缺失"
	}
	args, err := commandArgs(a.Uninstall)
	if err != nil || len(args) == 0 {
		return "卸载入口无法解析"
	}
	loc, err := absoluteUninstallExe(args[0])
	if err != nil {
		return "卸载入口受限/缺失"
	}
	return "已发现：" + loc
}

type uninstallOutcome struct {
	Message         string
	Next            safecore.NextStep
	Accepted        bool
	RebootRequired  bool
	RegisteredKnown bool
	StillRegistered bool
}

func observedOutcome(msg string, accepted, known, registered, reboot bool) uninstallOutcome {
	return uninstallOutcome{Message: msg, Accepted: accepted, RebootRequired: reboot, RegisteredKnown: known, StillRegistered: registered, Next: safecore.DecideBatchStep(safecore.UninstallStep{
		ExitAccepted: accepted, RegisteredKnown: known, StillRegistered: registered, RebootRequired: reboot,
	})}
}
func systemMSIExe() (string, error) {
	dir, e := windowsSystemDir()
	if e != nil {
		return "", e
	}
	p := filepath.Join(dir, "msiexec.exe")
	stat, e := os.Stat(p)
	if e != nil || !stat.Mode().IsRegular() {
		return "", fmt.Errorf("系统 msiexec.exe 不可访问：%v", e)
	}
	return p, nil
}
func uninstallOne(a appEntry) (uninstallOutcome, error) {
	exists, checkErr := registrationState(a)
	if checkErr != nil {
		return uninstallOutcome{}, fmt.Errorf("卸载前无法核验软件登记：%w", checkErr)
	}
	if !exists {
		return observedOutcome("注册项已不存在；无需重复卸载", true, true, false, false), nil
	}
	if productCode := matcher.MSIProductCode(a.KeyName, a.Uninstall, a.Msi); productCode != "" {
		if e := checkMSIIdentity(productCode); e != nil {
			return uninstallOutcome{}, e
		}
		msiexec, e := systemMSIExe()
		if e != nil {
			return uninstallOutcome{}, e
		}
		report := reportFile()
		if report == "" {
			return uninstallOutcome{}, errors.New("无法建立可信日志目录，拒绝运行 MSI")
		}
		logFile := filepath.Join(filepath.Dir(report), "MSI_"+strings.Trim(productCode, `{}`)+"_"+time.Now().Format("20060102_150405")+".log")
		cmd := exec.Command(msiexec, "/x", productCode, "/norestart", "/L*v", logFile)
		runErr := cmd.Run()
		exitCode := 0
		if runErr != nil {
			var exit *exec.ExitError
			if errors.As(runErr, &exit) {
				exitCode = exit.ExitCode()
			} else {
				return uninstallOutcome{}, fmt.Errorf("MSI 无法启动：%w", runErr)
			}
		}
		desc, needReboot, accepted := safecore.MSIResult(exitCode)
		exists, e := registrationState(a)
		if e != nil {
			return observedOutcome(desc+"；MSI日志："+logFile+"；注册表复查失败："+e.Error(), accepted, false, false, needReboot), nil
		}
		status := "注册项已消失（仍须重启/深度检查）"
		if exists {
			status = "注册项仍存在（可能未完成）"
		}
		return observedOutcome(desc+"；"+status+"；MSI日志："+logFile, accepted, true, exists, needReboot), nil
	}
	args, err := commandArgs(a.Uninstall)
	if err != nil {
		return uninstallOutcome{}, err
	}
	exe := args[0]
	location, err := absoluteUninstallExe(exe)
	if err != nil {
		return uninstallOutcome{}, err
	}
	if err := checkVendorSignature(exe); err != nil {
		return uninstallOutcome{}, err
	}
	// Launch directly; never pass registration content to cmd.exe or PowerShell.
	c := exec.Command(exe, args[1:]...)
	c.Dir = filepath.Dir(exe)
	runErr := c.Run()
	if runErr != nil {
		return observedOutcome("卸载器执行失败："+runErr.Error(), false, false, false, false), nil
	}
	// Some uninstallers exit after spawning a second process. Do not chain
	// another uninstall if the registration remains at the next observation.
	exists, e := registrationState(a)
	if e != nil {
		return observedOutcome("卸载器已退出（"+location+"），注册表复查失败："+e.Error(), true, false, false, false), nil
	}
	if exists {
		time.Sleep(2 * time.Second)
		exists, e = registrationState(a)
		if e != nil {
			return observedOutcome("卸载器已退出，但二次复查失败："+e.Error(), true, false, false, false), nil
		}
	}
	status := "注册项已消失（仍须重启/深度检查）"
	if exists {
		status = "注册项仍存在，可能还有后台卸载子进程"
	}
	out := observedOutcome("卸载器返回（"+location+"）；"+status, true, true, exists, false)
	// Vendor EXE uninstallers may spawn asynchronous descendants. Even when the
	// uninstall registration disappears, do not run the next uninstaller
	// without a user-driven rescan and explicit selection.
	out.Next = safecore.NextStep{Reason: "EXE 卸载器可能仍有异步子进程；请完成本次复查，再手动卸载下一项"}
	return out, nil
}

func residualFolders() ([]string, error) {
	paths := []string{}
	var scanError error
	roots := []struct {
		id      int
		folders []string
	}{
		{csidlProgramFiles, []string{"360", "360Safe", "Qihoo 360"}},
		{csidlProgramFilesX86, []string{"360", "360Safe", "Qihoo 360"}},
		{csidlCommonAppData, []string{"360", "360Safe", "360Security", "Qihoo 360"}},
		{csidlLocalAppData, []string{"360", "360Chrome", "360se6", "360zip", "360Security", "Qihoo 360"}},
		{csidlAppData, []string{"360", "360se6", "360Chrome", "Qihoo 360"}},
	}
	seen := map[string]bool{}
	for _, r := range roots {
		root, e := knownFolder(r.id)
		if e != nil {
			if scanError == nil {
				scanError = e
			}
			continue
		}
		for _, folder := range r.folders {
			s := filepath.Clean(filepath.Join(root, folder))
			if seen[strings.ToLower(s)] {
				continue
			}
			seen[strings.ToLower(s)] = true
			if info, e := os.Lstat(s); e == nil && info.IsDir() {
				paths = append(paths, s)
			} else if e != nil && !os.IsNotExist(e) && scanError == nil {
				scanError = fmt.Errorf("目录 %s 无法读取：%w", s, e)
			}
		}
	}
	return paths, scanError
}
func residualRegistry() ([]string, error) {
	checks := []struct {
		h          syscall.Handle
		name, path string
		view       uint32
	}{
		{syscall.HKEY_CURRENT_USER, "HKCU", `SOFTWARE\360`, 0},
		{syscall.HKEY_CURRENT_USER, "HKCU", `SOFTWARE\Qihoo`, 0},
		{syscall.HKEY_LOCAL_MACHINE, "HKLM", `SOFTWARE\360`, syscall.KEY_WOW64_64KEY},
		{syscall.HKEY_LOCAL_MACHINE, "HKLM", `SOFTWARE\360`, syscall.KEY_WOW64_32KEY},
		{syscall.HKEY_LOCAL_MACHINE, "HKLM", `SOFTWARE\Qihoo`, syscall.KEY_WOW64_64KEY},
	}
	out := []string{}
	var scanError error
	for _, r := range checks {
		found, err := keyExistsChecked(r.h, r.path, r.view)
		if err != nil && scanError == nil {
			scanError = fmt.Errorf("注册表线索检查失败 %s\\%s: %w", r.name, r.path, err)
		}
		if found {
			out = append(out, fmt.Sprintf("%s\\%s (%d 位视图)", r.name, r.path, func() int {
				if r.view == syscall.KEY_WOW64_32KEY {
					return 32
				}
				return 64
			}()))
		}
	}
	return out, scanError
}
func reportFile() string {
	base, e := userDataDir()
	if e != nil {
		return ""
	}
	dir := filepath.Join(base, "Reports")
	if e = os.MkdirAll(dir, 0700); e != nil {
		return ""
	}
	resolved, e := filepath.EvalSymlinks(dir)
	if e != nil || !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(dir)) {
		return ""
	}
	return filepath.Join(dir, "卸载记录_"+time.Now().Format("20060102_150405")+".txt")
}
