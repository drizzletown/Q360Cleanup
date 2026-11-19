//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func windowsSystemDir() (string, error) {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")
	buf := make([]uint16, 32768)
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 || int(r) >= len(buf) {
		return "", errors.New("GetSystemDirectoryW 无法定位系统目录")
	}
	return filepath.Clean(syscall.UTF16ToString(buf[:r])), nil
}

const (
	csidlAppData         = 0x001a
	csidlLocalAppData    = 0x001c
	csidlCommonAppData   = 0x0023
	csidlProgramFiles    = 0x0026
	csidlProgramFilesX86 = 0x002a
	csidlProfile         = 0x0028
)

// SHGetFolderPathW consults Windows' shell folder definition instead of trusting
// a caller-provided environment variable (LOCALAPPDATA/ProgramFiles/SystemRoot).
func knownFolder(csidl int) (string, error) {
	proc := syscall.NewLazyDLL("shell32.dll").NewProc("SHGetFolderPathW")
	buf := make([]uint16, 32768)
	r, _, _ := proc.Call(0, uintptr(csidl), 0, 0, uintptr(unsafe.Pointer(&buf[0])))
	if int32(r) != 0 {
		return "", fmt.Errorf("SHGetFolderPathW(%#x) 返回 HRESULT %#x", csidl, r)
	}
	p := filepath.Clean(syscall.UTF16ToString(buf))
	if !filepath.IsAbs(p) || strings.HasPrefix(p, `\\`) {
		return "", errors.New("系统文件夹不是本地绝对路径")
	}
	return p, nil
}

func verifiedLocalAppData() (string, error) {
	local, e := knownFolder(csidlLocalAppData)
	if e != nil {
		return "", e
	}
	profile, e := knownFolder(csidlProfile)
	if e != nil {
		return "", e
	}
	rel, e := filepath.Rel(profile, local)
	if e != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..\`) || filepath.IsAbs(rel) {
		return "", errors.New("当前用户 LocalAppData 不在实际用户配置文件内，拒绝写入隔离状态")
	}
	resolved, e := filepath.EvalSymlinks(local)
	if e != nil || !strings.EqualFold(filepath.Clean(resolved), local) {
		return "", errors.New("LocalAppData 路径不存在或含联接点重定向")
	}
	return local, nil
}
