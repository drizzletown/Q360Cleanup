//go:build windows

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"q360cleanup/matcher"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const uninstallRoot = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

type appEntry struct {
	Name, Publisher, Version, Uninstall, InstallPath, KeyName, RootName, Detection string
	Root                                                                           syscall.Handle
	View                                                                           uint32
	Msi                                                                            bool
	High                                                                           bool
}

func openReg(root syscall.Handle, path string, view uint32) (syscall.Handle, error) {
	var h syscall.Handle
	err := syscall.RegOpenKeyEx(root, syscall.StringToUTF16Ptr(path), 0, syscall.KEY_READ|view, &h)
	return h, err
}
func namesChecked(h syscall.Handle) ([]string, error) {
	result := []string{}
	for i := uint32(0); i < 100000; i++ {
		n := make([]uint16, 16384)
		sz := uint32(len(n))
		err := syscall.RegEnumKeyEx(h, i, &n[0], &sz, nil, nil, nil, nil)
		if err == syscall.Errno(259) {
			return result, nil
		} // ERROR_NO_MORE_ITEMS
		if err != nil {
			return result, fmt.Errorf("读取注册表子项 %d: %w", i, err)
		}
		result = append(result, syscall.UTF16ToString(n[:sz]))
	}
	return result, fmt.Errorf("注册表子项超过 100000 个，上限内扫描不完整")
}
func names(h syscall.Handle) []string { result, _ := namesChecked(h); return result }
func regString(h syscall.Handle, value string) string {
	var typ uint32
	var size uint32
	err := syscall.RegQueryValueEx(h, syscall.StringToUTF16Ptr(value), nil, &typ, nil, &size)
	if err != nil || size == 0 || size > 1<<20 || (typ != syscall.REG_SZ && typ != syscall.REG_EXPAND_SZ) {
		return ""
	}
	data := make([]byte, size)
	err = syscall.RegQueryValueEx(h, syscall.StringToUTF16Ptr(value), nil, &typ, &data[0], &size)
	if err != nil {
		return ""
	}
	us := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < int(size); i += 2 {
		us = append(us, binary.LittleEndian.Uint16(data[i:i+2]))
	}
	text := string(utf16.Decode(us))
	text = strings.TrimRight(text, "\x00")
	if typ == syscall.REG_EXPAND_SZ {
		text = expandWindows(text)
	}
	return text
}
func regDword(h syscall.Handle, value string) uint32 {
	var typ uint32
	size := uint32(4)
	data := [4]byte{}
	err := syscall.RegQueryValueEx(h, syscall.StringToUTF16Ptr(value), nil, &typ, &data[0], &size)
	if err != nil || typ != syscall.REG_DWORD || size != 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(data[:])
}
func registryScan() []appEntry { entries, _ := registryScanChecked(); return entries }

func registryScanChecked() ([]appEntry, []string) {
	entries := []appEntry{}
	scanErrors := []string{}
	seen := map[string]bool{}
	roots := []struct {
		label string
		key   syscall.Handle
	}{{"当前用户", syscall.HKEY_CURRENT_USER}, {"本机", syscall.HKEY_LOCAL_MACHINE}}
	views := []struct {
		label string
		view  uint32
	}{{"64位", syscall.KEY_WOW64_64KEY}, {"32位", syscall.KEY_WOW64_32KEY}}
	for _, root := range roots {
		for _, v := range views {
			base, e := openReg(root.key, uninstallRoot, v.view)
			if e != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("%s %s 卸载项读取失败：%v", root.label, v.label, e))
				continue
			}
			subkeys, enumErr := namesChecked(base)
			if enumErr != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("%s %s 卸载项枚举不完整：%v", root.label, v.label, enumErr))
			}
			for _, sub := range subkeys {
				k, e := openReg(base, sub, 0)
				if e != nil {
					scanErrors = append(scanErrors, fmt.Sprintf("%s %s 软件 %s 注册项无法读取：%v", root.label, v.label, sub, e))
					continue
				}
				display := regString(k, "DisplayName")
				publisher := regString(k, "Publisher")
				dec := matcher.Classify(display, publisher)
				if dec.Match {
					id := fmt.Sprintf("%s:%d:%s", root.label, v.view, strings.ToLower(sub))
					if !seen[id] {
						seen[id] = true
						entries = append(entries, appEntry{
							Name: display, Publisher: publisher, Version: regString(k, "DisplayVersion"),
							Uninstall: regString(k, "UninstallString"), InstallPath: regString(k, "InstallLocation"),
							KeyName: sub, RootName: root.label, Root: root.key, View: v.view,
							Msi: regDword(k, "WindowsInstaller") == 1, High: dec.HighConfidence, Detection: dec.Reason,
						})
					}
				}
				syscall.RegCloseKey(k)
			}
			syscall.RegCloseKey(base)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].High != entries[j].High {
			return entries[i].High
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries, scanErrors
}

// registrationState preserves read errors as unknown, never as a false success.
func registrationState(a appEntry) (bool, error) {
	base, err := openReg(a.Root, uninstallRoot, a.View)
	if err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return false, nil
		}
		return false, err
	}
	defer syscall.RegCloseKey(base)
	sub, err := openReg(base, a.KeyName, 0)
	if err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return false, nil
		}
		return false, err
	}
	defer syscall.RegCloseKey(sub)
	return true, nil
}
func keyExistsChecked(root syscall.Handle, path string, view uint32) (bool, error) {
	h, err := openReg(root, path, view)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	syscall.RegCloseKey(h)
	return true, nil
}
func keyExists(root syscall.Handle, path string, view uint32) bool {
	h, err := openReg(root, path, view)
	if err != nil {
		return false
	}
	syscall.RegCloseKey(h)
	return true
}
func expandWindows(in string) string {
	// ExpandEnvironmentStringsW avoids invoking a shell.
	p := syscall.NewLazyDLL("kernel32.dll").NewProc("ExpandEnvironmentStringsW")
	src := syscall.StringToUTF16Ptr(in)
	n, _, _ := p.Call(uintptr(unsafe.Pointer(src)), 0, 0)
	if n == 0 || n > 32767 {
		return in
	}
	buf := make([]uint16, n)
	ret, _, _ := p.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(&buf[0])), uintptr(n))
	if ret == 0 || ret > n {
		return in
	}
	return syscall.UTF16ToString(buf)
}

// The following persistence locations are audited read-only. Neither services,
// protected drivers nor startup entries are stopped, disabled or removed.
func related360(name, command string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	c := strings.ToLower(strings.ReplaceAll(command, "/", `\`))
	if strings.HasPrefix(n, "360") || strings.Contains(n, "qihoo") || strings.Contains(n, "奇虎") {
		return true
	}
	for _, token := range []string{`\360\`, `\360safe`, `\360sd`, `\360chrome`, `\360se6`, `\qihoo`, `\qihu`, `\360zip`} {
		if strings.Contains(c, token) {
			return true
		}
	}
	return false
}
func residualServices() ([]string, error) {
	out := []string{}
	root, e := openReg(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, 0)
	if e != nil {
		return out, e
	}
	defer syscall.RegCloseKey(root)
	subkeys, enumErr := namesChecked(root)
	for _, sub := range subkeys {
		k, e := openReg(root, sub, 0)
		if e != nil {
			if enumErr == nil {
				enumErr = fmt.Errorf("无法读取服务项 %s: %w", sub, e)
			}
			continue
		}
		display := regString(k, "DisplayName")
		image := regString(k, "ImagePath")
		if related360(sub, image) || related360(display, image) {
			t := regDword(k, "Type")
			kind := "服务"
			if t&1 != 0 || t&2 != 0 {
				kind = "内核/文件系统驱动"
			}
			out = append(out, fmt.Sprintf("%s | %s | %s | 路径=%s", kind, sub, display, image))
		}
		syscall.RegCloseKey(k)
	}
	return out, enumErr
}
func enumValueNames(h syscall.Handle) ([]string, error) {
	proc := syscall.NewLazyDLL("advapi32.dll").NewProc("RegEnumValueW")
	out := []string{}
	for i := uint32(0); i < 100000; i++ {
		buf := make([]uint16, 16384)
		n := uint32(len(buf))
		r, _, _ := proc.Call(uintptr(h), uintptr(i), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0, 0, 0, 0)
		if r == 259 {
			return out, nil
		}
		if r != 0 {
			return out, fmt.Errorf("注册表值枚举第 %d 项失败：Win32 %d", i, r)
		}
		out = append(out, syscall.UTF16ToString(buf[:n]))
	}
	return out, errors.New("注册表自启动项超过 100000 项，扫描不完整")
}
func residualStartup() ([]string, error) {
	out := []string{}
	var firstError error
	for _, root := range []struct {
		h     syscall.Handle
		label string
	}{{syscall.HKEY_LOCAL_MACHINE, "HKLM"}, {syscall.HKEY_CURRENT_USER, "HKCU"}} {
		for _, view := range []uint32{syscall.KEY_WOW64_64KEY, syscall.KEY_WOW64_32KEY} {
			for _, sub := range []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`} {
				h, e := openReg(root.h, sub, view)
				if e != nil {
					continue
				}
				keys, e := enumValueNames(h)
				if e != nil && firstError == nil {
					firstError = e
				}
				for _, key := range keys {
					cmd := regString(h, key)
					if related360(key, cmd) {
						out = append(out, fmt.Sprintf("%s\\%s | %s = %s", root.label, sub, key, cmd))
					}
				}
				syscall.RegCloseKey(h)
			}
		}
	}
	// Registry's 64/32 view of a Run key can refer to the same underlying value.
	dedupe := map[string]bool{}
	clean := []string{}
	for _, x := range out {
		if !dedupe[x] {
			dedupe[x] = true
			clean = append(clean, x)
		}
	}
	return clean, firstError
}

// Managed endpoint products are never eligible for automatic cleanup.
func hasManaged360() (bool, error) {
	forbidden := []string{"企业版", "企业安全", "政企", "终端安全", "天擎", "天鉴", "edr", "endpoint", "enterprise", "business", "管理中心", "集中管理", "服务器版"}
	for _, root := range []syscall.Handle{syscall.HKEY_CURRENT_USER, syscall.HKEY_LOCAL_MACHINE} {
		for _, view := range []uint32{syscall.KEY_WOW64_64KEY, syscall.KEY_WOW64_32KEY} {
			base, e := openReg(root, uninstallRoot, view)
			if e != nil {
				return false, e
			}
			subkeys, e := namesChecked(base)
			if e != nil {
				syscall.RegCloseKey(base)
				return false, e
			}
			for _, sub := range subkeys {
				k, e := openReg(base, sub, 0)
				if e != nil {
					syscall.RegCloseKey(base)
					return false, e
				}
				name := strings.ToLower(regString(k, "DisplayName"))
				vendor := strings.ToLower(regString(k, "Publisher"))
				syscall.RegCloseKey(k)
				if !(strings.HasPrefix(name, "360") || strings.HasPrefix(name, "奇虎") || strings.HasPrefix(name, "qihoo") || strings.Contains(vendor, "qihoo") || strings.Contains(vendor, "奇虎")) {
					continue
				}
				for _, word := range forbidden {
					if strings.Contains(name, word) {
						syscall.RegCloseKey(base)
						return true, nil
					}
				}
			}
			syscall.RegCloseKey(base)
		}
	}
	return false, nil
}
