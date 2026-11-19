//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// checkVendorSignature is deliberately conservative. A plausible path is not
// evidence of publisher identity when launching a program with admin rights.
// Windows' own Authenticode provider checks signature trust and certificate
// chain. Unknown/unsigned legacy uninstallers require manual vendor support.
func checkVendorSignature(path string) error {
	systemDir, e := windowsSystemDir()
	if e != nil {
		return e
	}
	shell := filepath.Join(filepath.Dir(systemDir), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if info, e := os.Stat(shell); e != nil || !info.Mode().IsRegular() {
		return errors.New("无法访问系统 PowerShell 签名核验功能；拒绝提权运行 EXE")
	}
	// The file path is passed only through the environment. It is never
	// interpolated into PowerShell code, preventing command injection.
	script := `$s = Get-AuthenticodeSignature -LiteralPath $env:Q360_VERIFY_EXE; ` +
		`if ($s.Status -eq 'Valid' -and $null -ne $s.SignerCertificate -and ` +
		`$s.SignerCertificate.Subject -match '(?i)(qihoo|qi\s*hu|qihu|三六零|奇虎|360)') ` +
		`{ [Console]::Write('OK'); exit 0 } ` +
		`else { [Console]::Write('UNTRUSTED'); exit 3 }`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-NoProfile", "-NonInteractive", "-Command", script)
	// Do not inherit user-controlled PATH, PSModulePath, or other startup
	// environment that could influence an elevated PowerShell invocation.
	winDir := filepath.Dir(systemDir)
	profile, e := knownFolder(csidlProfile)
	if e != nil {
		return e
	}
	cmd.Env = []string{
		"SystemRoot=" + winDir, "WINDIR=" + winDir,
		"PATH=" + systemDir,
		"PSModulePath=" + filepath.Join(winDir, "System32", "WindowsPowerShell", "v1.0", "Modules"),
		"USERPROFILE=" + profile,
		"Q360_VERIFY_EXE=" + path,
	}
	out, e := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("签名检查超时：%w", ctx.Err())
	}
	if e != nil || !strings.EqualFold(strings.TrimSpace(string(out)), "OK") {
		return errors.New("卸载器的 Windows Authenticode 签名不可信或非识别的 360 厂商；请使用 Windows 卸载界面或联系官方修复")
	}
	return nil
}
