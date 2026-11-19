//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"q360cleanup/safecore"
	"strings"
	"time"
)

func userDataDir() (string, error) {
	base, e := verifiedLocalAppData()
	if e != nil {
		return "", e
	}
	dir := filepath.Join(base, "Q360Cleanup")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	resolved, e := filepath.EvalSymlinks(dir)
	if e != nil || !strings.EqualFold(filepath.Clean(resolved), filepath.Clean(dir)) {
		return "", errors.New("状态目录存在联接点或不可读取，拒绝提权写入")
	}
	return dir, nil
}

type targetRecord struct {
	Name       string `json:"name"`
	Publisher  string `json:"publisher"`
	RegistryID string `json:"registry_id"`
	State      string `json:"state"` // pending, running, verified, reboot_pending, blocked, failed
	Detail     string `json:"detail,omitempty"`
}

type sessionRecord struct {
	Version  int            `json:"version"`
	Started  time.Time      `json:"started"`
	BootTime time.Time      `json:"boot_time"`
	Targets  []targetRecord `json:"targets"`
}

func sessionPath() (string, error) {
	base, e := userDataDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(base, "last_session.json"), nil
}
func saveSession(targets []appEntry) error {
	path, e := sessionPath()
	if e != nil {
		return e
	}
	return saveSessionAt(path, targets)
}
func saveSessionAt(path string, targets []appEntry) error {
	if len(targets) == 0 {
		return errors.New("没有选择目标产品")
	}
	names := make([]targetRecord, 0, len(targets))
	for _, a := range targets {
		names = append(names, targetRecord{
			Name: a.Name, Publisher: a.Publisher,
			RegistryID: fmt.Sprintf("%s:%d:%s", a.RootName, a.View, a.KeyName),
			State:      "pending",
		})
	}
	return safecore.SaveJSONAtomic(path, sessionRecord{Version: 2, Started: time.Now(), BootTime: currentBootTime(), Targets: names})
}
func loadSession() (sessionRecord, bool, error) {
	p, e := sessionPath()
	if e != nil {
		return sessionRecord{}, false, e
	}
	return loadSessionAt(p)
}
func loadSessionAt(p string) (sessionRecord, bool, error) {
	b, e := os.ReadFile(p)
	if os.IsNotExist(e) {
		return sessionRecord{}, false, nil
	}
	if e != nil {
		return sessionRecord{}, false, e
	}
	if len(b) > 1024*1024 {
		return sessionRecord{}, false, errors.New("验收会话文件异常过大")
	}
	var s sessionRecord
	if e = json.Unmarshal(b, &s); e != nil {
		return s, false, e
	}
	if s.Version != 2 || s.Started.IsZero() || s.BootTime.IsZero() || len(s.Targets) == 0 || len(s.Targets) > 256 {
		return s, false, errors.New("验收会话格式不兼容或损坏，无法给出通过结论")
	}
	for _, target := range s.Targets {
		if target.RegistryID == "" || target.Name == "" || !safecore.ValidTargetState(target.State) {
			return s, false, errors.New("验收会话含有非法状态")
		}
	}
	return s, true, nil
}
func setTargetState(index int, state, detail string) error {
	path, e := sessionPath()
	if e != nil {
		return e
	}
	return setTargetStateAt(path, index, state, detail)
}
func setTargetStateAt(path string, index int, state, detail string) error {
	s, found, e := loadSessionAt(path)
	if e != nil {
		return e
	}
	if !found || index < 0 || index >= len(s.Targets) {
		return errors.New("验收会话已丢失或目标索引错误")
	}
	old := s.Targets[index].State
	if !safecore.ValidTransition(old, state) {
		return fmt.Errorf("拒绝卸载状态非法转换 %s -> %s", old, state)
	}
	s.Targets[index].State = state
	s.Targets[index].Detail = detail
	return safecore.SaveJSONAtomic(path, s)
}

// A failed/pending/unknown target can never be certified as successfully removed.
// All targets must have a recorded accepted uninstaller result. Reboot-pending
// remains conditional on a reboot being detected and the audit finding no remnants.
func workflowEvidence(s sessionRecord, exists, reboot bool) (failed, incomplete bool) {
	if !exists {
		return false, false
	}
	for _, target := range s.Targets {
		switch target.State {
		case "verified":
		case "reboot_pending":
			// It is an accepted uninstall awaiting the global reboot gate.
		case "failed", "blocked":
			failed = true
		default:
			incomplete = true
		}
	}
	return
}

type isolationRecord = safecore.IsolationRecord
type isolationJournal = safecore.IsolationJournal

func isolationStore() (safecore.IsolationStore, error) {
	dir, e := userDataDir()
	if e != nil {
		return safecore.IsolationStore{}, e
	}
	programData, e := knownFolder(csidlCommonAppData)
	if e != nil {
		return safecore.IsolationStore{}, e
	}
	localData, e := verifiedLocalAppData()
	if e != nil {
		return safecore.IsolationStore{}, e
	}
	appData, e := knownFolder(csidlAppData)
	if e != nil {
		return safecore.IsolationStore{}, e
	}
	return safecore.IsolationStore{DataDir: dir, Roots: map[string]string{
		"ProgramData": programData, "LOCALAPPDATA": localData, "APPDATA": appData,
	}}, nil
}
func loadJournal() (isolationJournal, error) {
	s, e := isolationStore()
	if e != nil {
		return isolationJournal{}, e
	}
	return s.LoadReconciled()
}
func journalActive(j isolationJournal) int { return j.Active() }
func quarantineFolder(path string) (isolationRecord, error) {
	s, e := isolationStore()
	if e != nil {
		return isolationRecord{}, e
	}
	return s.Quarantine(path)
}
func restoreAll() ([]string, error) {
	s, e := isolationStore()
	if e != nil {
		return nil, e
	}
	return s.RestoreAll()
}
