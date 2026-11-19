//go:build windows

package main

import (
	"os"
	"path/filepath"
	"q360cleanup/safecore"
	"strings"
	"testing"
	"time"
)

// Windows-native tests do not uninstall or modify any third-party software.
func TestWindowsSessionPersistence(t *testing.T) {
	file := filepath.Join(t.TempDir(), "session.json")
	targets := []appEntry{{Name: "360安全卫士", Publisher: "奇虎科技", RootName: "本机", KeyName: "fake-guid", View: 0}}
	if e := saveSessionAt(file, targets); e != nil {
		t.Fatal(e)
	}
	s, found, e := loadSessionAt(file)
	if e != nil || !found || len(s.Targets) != 1 || s.Targets[0].State != "pending" {
		t.Fatalf("initial state %+v %v %v", s, found, e)
	}
	if e := setTargetStateAt(file, 0, "verified", "invalid transition"); e == nil {
		t.Fatal("pending -> verified must be refused")
	}
	if e := setTargetStateAt(file, 0, "running", "starting"); e != nil {
		t.Fatal(e)
	}
	if e := setTargetStateAt(file, 0, "failed", "uninstaller error"); e != nil {
		t.Fatal(e)
	}
	s, found, e = loadSessionAt(file)
	if e != nil || !found || s.Targets[0].State != "failed" {
		t.Fatalf("persistence failed %+v %v", s, e)
	}
	failed, incomplete := workflowEvidence(s, true, true)
	if !failed || incomplete {
		t.Fatalf("failure was not retained: %v,%v", failed, incomplete)
	}
	if e := setTargetStateAt(file, 0, "verified", "attempt overwrite"); e == nil {
		t.Fatal("rewrote failed state to success")
	}
}
func TestWindowsSessionCorruptionFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "session.json")
	if e := os.WriteFile(p, []byte(`{"version":2,"targets":[{"state":"verified"}]}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, found, e := loadSessionAt(p); e == nil || found {
		t.Fatalf("invalid state accepted: %v %v", found, e)
	}
}
func TestWindowsUnsignedSignatureRejected(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "uninst.exe")
	if e := os.WriteFile(fake, []byte("not a signed PE image"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := checkVendorSignature(fake); e == nil {
		t.Fatal("unsigned uninstaller accepted")
	}
}
func TestWindowsSystemPathsIgnoreSpoofedEnvironment(t *testing.T) {
	trueDir, e := windowsSystemDir()
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("SystemRoot", t.TempDir())
	t.Setenv("WINDIR", t.TempDir())
	t.Setenv("ProgramFiles", t.TempDir())
	actual, e := windowsSystemDir()
	if e != nil || !strings.EqualFold(actual, trueDir) {
		t.Fatalf("system root redirected by environment: %q -> %q (%v)", trueDir, actual, e)
	}
	exe, e := systemMSIExe()
	if e != nil || !strings.EqualFold(filepath.Dir(exe), trueDir) {
		t.Fatalf("msiexec came from spoofed directory: %q, %v", exe, e)
	}
}
func TestWindowsKnownFoldersIgnoreSpoofedEnvironment(t *testing.T) {
	original, e := knownFolder(csidlLocalAppData)
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	current, e := knownFolder(csidlLocalAppData)
	if e != nil || !strings.EqualFold(original, current) {
		t.Fatalf("known-folder root changed by env: %q -> %q (%v)", original, current, e)
	}
}
func TestWindowsMSIIdentityNotForged(t *testing.T) {
	if e := checkMSIIdentity("{00000000-0000-0000-0000-000000000001}"); e == nil {
		t.Fatal("missing MSI product accepted")
	}
}
func TestWindowsRegisteredUninstallerNotRunFromTemp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "360Safe")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	exe := filepath.Join(dir, "uninst.exe")
	if e := os.WriteFile(exe, []byte("fake binary"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := absoluteUninstallExe(exe); e == nil {
		t.Fatal("untrusted temp uninstaller accepted")
	}
}
func TestWindowsNoTargetAuditIsReadOnly(t *testing.T) {
	// This probes native enumeration without asserting a specific machine state.
	// No removal, service mutation or registry writing is performed.
	a := collectAudit()
	if a.Timestamp.IsZero() || a.BootTime.IsZero() {
		t.Fatal("audit timestamps missing")
	}
	if a.Timestamp.Sub(a.BootTime) < 0 {
		t.Fatal("boot timestamp later than scan")
	}
	for _, msg := range a.Errors {
		t.Log("read-only audit limitation:", msg)
	}
}
func TestWindowsRebootInterpretationDoesNotAcceptSameBoot(t *testing.T) {
	now := time.Now()
	boot := currentBootTime()
	if safecore.RebootAfter(now, boot, currentBootTime()) {
		t.Fatal("same boot detected as a new boot")
	}
	if !strings.Contains(strings.ToLower(filepath.Base(os.Args[0])), "test") {
		t.Log("test binary name differs from expected convention")
	}
}

func TestWindowsRebootPendingRequiresRebootAndAudit(t *testing.T) {
	s := sessionRecord{Targets: []targetRecord{{State: "reboot_pending"}}}
	failed, incomplete := workflowEvidence(s, true, false)
	if failed || incomplete {
		t.Fatalf("accepted reboot-pending result marked failure: %v %v", failed, incomplete)
	}
	evidence := safecore.Evidence{SessionExists: true, RebootObserved: false, WorkflowFailed: failed, WorkflowIncomplete: incomplete}
	if result := safecore.Assess(evidence); result.Level != "等待重启" {
		t.Fatalf("should await reboot, got %+v", result)
	}
	evidence.RebootObserved = true
	evidence.Installed = 1
	if result := safecore.Assess(evidence); result.Level != "未完成" {
		t.Fatalf("still-installed product passed: %+v", result)
	}
}
func TestWindowsPendingTargetPreventsSuccess(t *testing.T) {
	s := sessionRecord{Targets: []targetRecord{{State: "verified"}, {State: "pending"}}}
	failed, incomplete := workflowEvidence(s, true, true)
	if failed || !incomplete {
		t.Fatalf("pending target not marked incomplete: %v %v", failed, incomplete)
	}
}

// A caller-controlled WINDIR must never redirect task enumeration outside Windows.
func TestWindowsTasksIgnoreSpoofedSystemRoot(t *testing.T) {
	root := t.TempDir()
	fake := filepath.Join(root, "System32", "Tasks")
	if err := os.MkdirAll(fake, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fake, "360Safe-TestSpoof"), []byte("fake"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WINDIR", root)
	t.Setenv("SystemRoot", root)
	tasks, err := residualTasks()
	if err != nil {
		t.Skipf("Cannot read system task files in this runner: %v", err)
	}
	for _, task := range tasks {
		if strings.Contains(task, "360Safe-TestSpoof") {
			t.Fatalf("spoofed task directory accepted: %s", task)
		}
	}
}
