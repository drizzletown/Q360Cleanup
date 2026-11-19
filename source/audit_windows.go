//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"q360cleanup/safecore"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

type auditSnapshot struct {
	Timestamp                                              time.Time
	BootTime                                               time.Time
	Products                                               []appEntry
	Folders, Registry, Services, Startup, Processes, Tasks []string
	Errors                                                 []string
}

func currentBootTime() time.Time {
	r, _, _ := kernel32.NewProc("GetTickCount64").Call()
	// Date is an approximate boot time; enough for detecting a new boot session.
	return time.Now().Add(-time.Duration(uint64(r)) * time.Millisecond)
}

func residualProcesses() ([]string, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err = syscall.Process32First(snap, &entry); err != nil {
		return nil, err
	}
	out := []string{}
	open := kernel32.NewProc("OpenProcess")
	query := kernel32.NewProc("QueryFullProcessImageNameW")
	for {
		pid := entry.ProcessID
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if pid != 0 {
			handle, _, _ := open.Call(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, 0, uintptr(pid))
			if handle != 0 {
				buf := make([]uint16, 32768)
				n := uint32(len(buf))
				r, _, _ := query.Call(handle, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
				syscall.CloseHandle(syscall.Handle(handle))
				if r != 0 && n > 0 {
					path := string(utf16.Decode(buf[:n]))
					if related360(name, path) || safecore.TaskMatch(name, path) {
						out = append(out, fmt.Sprintf("PID=%d | %s | %s", pid, name, path))
					}
				} else if isKnown360Process(name) {
					out = append(out, fmt.Sprintf("PID=%d | %s | 路径无法读取，需人工核对", pid, name))
				}
			} else if isKnown360Process(name) {
				out = append(out, fmt.Sprintf("PID=%d | %s | 权限不足，无法读取进程路径", pid, name))
			}
		}
		if err = syscall.Process32Next(snap, &entry); err != nil {
			if err != syscall.ERROR_NO_MORE_FILES {
				return out, fmt.Errorf("Windows 进程枚举中断：%w", err)
			}
			break
		}
	}
	return out, nil
}
func isKnown360Process(name string) bool {
	n := strings.ToLower(name)
	for _, x := range []string{"360safe", "360sd", "360tray", "360se", "360chrome", "360zip", "360doctor", "qihoo"} {
		if strings.HasPrefix(n, x) && strings.HasSuffix(n, ".exe") {
			return true
		}
	}
	return false
}

func decodeTask(b []byte) string {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		us := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			us = append(us, binary.LittleEndian.Uint16(b[i:i+2]))
		}
		return string(utf16.Decode(us))
	}
	if len(b) >= 2 && b[0] == 0xfe && b[1] == 0xff {
		us := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			us = append(us, binary.BigEndian.Uint16(b[i:i+2]))
		}
		return string(utf16.Decode(us))
	}
	return string(b)
}
func residualTasks() ([]string, error) {
	systemDir, e := windowsSystemDir()
	if e != nil {
		return nil, fmt.Errorf("无法读取 Windows 系统任务目录：%w", e)
	}
	root := filepath.Join(systemDir, "Tasks")
	result := []string{}
	examined := 0
	var scanError error
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			if scanError == nil {
				scanError = e
			}
			return nil
		}
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		examined++
		if examined > 50000 {
			return fmt.Errorf("超过计划任务检查上限 50000")
		}
		name, _ := filepath.Rel(root, path)
		if d.Type().IsRegular() {
			info, e := d.Info()
			if e != nil {
				if scanError == nil {
					scanError = e
				}
				return nil
			}
			if info.Size() <= 1024*1024 {
				b, e := os.ReadFile(path)
				if e != nil {
					if scanError == nil {
						scanError = e
					}
					return nil
				}
				if safecore.TaskMatch(name, decodeTask(b)) {
					result = append(result, fmt.Sprintf("%s | %s", name, path))
				}
			} else if safecore.TaskMatch(name, "") {
				result = append(result, fmt.Sprintf("%s | %s | 文件过大，未读取内容", name, path))
			}
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	return result, scanError
}
func collectAudit() auditSnapshot {
	a := auditSnapshot{Timestamp: time.Now(), BootTime: currentBootTime()}
	products, errs := registryScanChecked()
	a.Products = products
	a.Errors = append(a.Errors, errs...)
	folders, err := residualFolders()
	a.Folders = folders
	if err != nil {
		a.Errors = append(a.Errors, "目录扫描不完整："+err.Error())
	}
	reg, err := residualRegistry()
	a.Registry = reg
	if err != nil {
		a.Errors = append(a.Errors, "注册表残留扫描不完整："+err.Error())
	}
	services, err := residualServices()
	a.Services = services
	if err != nil {
		a.Errors = append(a.Errors, "服务扫描不完整："+err.Error())
	}
	startup, err := residualStartup()
	a.Startup = startup
	if err != nil {
		a.Errors = append(a.Errors, "启动项扫描不完整："+err.Error())
	}
	p, e := residualProcesses()
	a.Processes = p
	if e != nil {
		a.Errors = append(a.Errors, "进程快照失败："+e.Error())
	}
	t, e := residualTasks()
	a.Tasks = t
	if e != nil {
		a.Errors = append(a.Errors, "计划任务清单不完整："+e.Error())
	}
	h, e := openReg(syscall.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, 0)
	if e != nil {
		a.Errors = append(a.Errors, "服务注册表无法读取："+e.Error())
	} else {
		syscall.RegCloseKey(h)
	}
	h, e = openReg(syscall.HKEY_LOCAL_MACHINE, uninstallRoot, syscall.KEY_WOW64_64KEY)
	if e != nil {
		a.Errors = append(a.Errors, "HKLM卸载注册项无法读取："+e.Error())
	} else {
		syscall.RegCloseKey(h)
	}
	return a
}
func auditEvidence(a auditSnapshot, s sessionRecord, exists bool, quarantined int) safecore.Evidence {
	reboot := exists && safecore.RebootAfter(s.Started, s.BootTime, a.BootTime)
	return safecore.Evidence{
		SessionExists: exists, RebootObserved: reboot, Installed: len(a.Products),
		Services: len(a.Services), Processes: len(a.Processes), Tasks: len(a.Tasks), Startup: len(a.Startup),
		Folders: len(a.Folders), Registry: len(a.Registry), QuarantinePending: quarantined, ScanError: len(a.Errors) > 0,
	}
}
