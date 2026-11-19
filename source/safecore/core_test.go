package safecore

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestQuarantineStrict(t *testing.T) {
	tmp := t.TempDir()
	roots := map[string]string{"LOCALAPPDATA": filepath.Join(tmp, "AppData", "Local"), "APPDATA": filepath.Join(tmp, "AppData", "Roaming"), "ProgramData": filepath.Join(tmp, "ProgramData"), "ProgramFiles": filepath.Join(tmp, "Program Files")}
	ok := filepath.Join(roots["LOCALAPPDATA"], "360se6")
	if _, a := QuarantinableDir(ok, roots); !a {
		t.Fatal("expected approved path")
	}
	for _, p := range []string{filepath.Join(roots["ProgramFiles"], "360"), filepath.Join(roots["LOCALAPPDATA"], "360se6", "User Data"), filepath.Join(roots["LOCALAPPDATA"], "360se6_foo"), roots["LOCALAPPDATA"], filepath.Join(tmp, "Windows", "System32"), "."} {
		if _, a := QuarantinableDir(p, roots); a {
			t.Errorf("incorrectly authorized %q", p)
		}
	}
	if _, a := QuarantinableDir(strings.TrimSuffix(ok, "6"), roots); a {
		t.Fatal("prefix allowed")
	}
}
func TestMSIStatuses(t *testing.T) {
	tests := []struct {
		code           int
		accept, reboot bool
	}{{0, true, false}, {3010, true, true}, {1641, true, true}, {1603, false, false}, {1602, false, false}, {1618, false, false}, {1612, false, false}, {999, false, false}}
	for _, tc := range tests {
		msg, reboot, accept := MSIResult(tc.code)
		if msg == "" || reboot != tc.reboot || accept != tc.accept {
			t.Fatalf("%d: %s %v %v", tc.code, msg, reboot, accept)
		}
	}
}
func TestVerdict(t *testing.T) {
	e := Evidence{SessionExists: true, RebootObserved: true}
	if v := Assess(e); v.Level != "范围内通过" {
		t.Fatal(v)
	}
	e.Installed = 1
	if v := Assess(e); v.Level != "未完成" {
		t.Fatal(v)
	}
	e.Installed = 0
	e.Services = 1
	if v := Assess(e); v.Level != "需人工处置" {
		t.Fatal(v)
	}
	e.Services = 0
	e.RebootObserved = false
	if v := Assess(e); v.Level != "等待重启" {
		t.Fatal(v)
	}
	e.RebootObserved = true
	e.Folders = 1
	if v := Assess(e); v.Level != "残留待确认" {
		t.Fatal(v)
	}
	e.Folders = 0
	e.ScanError = true
	if v := Assess(e); v.Level != "无法判定" {
		t.Fatal(v)
	}
}
func TestTaskMatch(t *testing.T) {
	yes := []struct{ n, c string }{{`\\360\\Scan`, ""}, {`360SafeUpdate`, ""}, {"OtherTask", `<Exec><Command>C:\\Program Files\\360Safe\\agent.exe</Command></Exec>`}, {"Qihoo updater", ""}}
	for _, x := range yes {
		if !TaskMatch(x.n, x.c) {
			t.Errorf("missed: %+v", x)
		}
	}
	for _, x := range []struct{ n, c string }{{`Fusion360_update`, ""}, {`Backup_360days`, ""}, {"Other", `C:\\Program Files\\Autodesk\\Fusion 360\\setup.exe`}} {
		if TaskMatch(x.n, x.c) {
			t.Errorf("false positive: %+v", x)
		}
	}
}
