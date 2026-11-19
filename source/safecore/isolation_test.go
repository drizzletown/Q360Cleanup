package safecore

import (
	"os"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) (IsolationStore, string) {
	t.Helper()
	root := t.TempDir()
	local := filepath.Join(root, "AppData", "Local")
	if err := os.MkdirAll(local, 0700); err != nil {
		t.Fatal(err)
	}
	return IsolationStore{DataDir: filepath.Join(local, "Q360Cleanup"), Roots: map[string]string{"LOCALAPPDATA": local}}, filepath.Join(local, "360se6")
}
func TestIsolationRoundTrip(t *testing.T) {
	s, p := testStore(t)
	if e := os.Mkdir(p, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(p, "bookmarks.txt"), []byte("precious"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := s.Quarantine(p)
	if e != nil {
		t.Fatal(e)
	}
	if r.State != "isolated" {
		t.Fatal(r)
	}
	if _, e := os.Lstat(p); !os.IsNotExist(e) {
		t.Fatalf("source not moved: %v", e)
	}
	if _, e := os.Stat(filepath.Join(r.Quarantine, "bookmarks.txt")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Quarantine(p); e == nil {
		t.Fatal("duplicate quarantine allowed")
	}
	messages, e := s.RestoreAll()
	if e != nil || len(messages) != 1 {
		t.Fatalf("restore %v %v", messages, e)
	}
	b, e := os.ReadFile(filepath.Join(p, "bookmarks.txt"))
	if e != nil || string(b) != "precious" {
		t.Fatalf("lost data: %s %v", b, e)
	}
	j, e := s.Load()
	if e != nil || j.Active() != 0 {
		t.Fatalf("journal %v %v", j, e)
	}
}
func TestIsolationRefusesOverwrite(t *testing.T) {
	s, p := testStore(t)
	os.Mkdir(p, 0700)
	os.WriteFile(filepath.Join(p, "old.txt"), []byte("old"), 0600)
	_, e := s.Quarantine(p)
	if e != nil {
		t.Fatal(e)
	}
	os.Mkdir(p, 0700)
	os.WriteFile(filepath.Join(p, "new.txt"), []byte("new"), 0600)
	messages, e := s.RestoreAll()
	if e != nil || len(messages) != 1 {
		t.Fatalf("restore %v %v", messages, e)
	}
	if _, e := os.Stat(filepath.Join(p, "new.txt")); e != nil {
		t.Fatal("overwrote new data", e)
	}
	j, _ := s.Load()
	if j.Active() != 1 {
		t.Fatal("journal incorrectly cleared")
	}
}
func TestIsolationRefusesOutOfScopeAndLinks(t *testing.T) {
	s, p := testStore(t)
	os.Mkdir(p, 0700)
	bad := filepath.Join(filepath.Dir(p), "Not360")
	os.Mkdir(bad, 0700)
	if _, e := s.Quarantine(bad); e == nil {
		t.Fatal("accepted other directory")
	}
	os.Remove(p)
	os.Symlink(bad, p)
	if _, e := s.Quarantine(p); e == nil {
		t.Fatal("accepted symlink")
	}
}
func TestInterruptedMoveRecovery(t *testing.T) {
	s, p := testStore(t)
	os.Mkdir(p, 0700)
	dest := filepath.Join(s.DataDir, "Quarantine", "recovered")
	os.MkdirAll(filepath.Dir(dest), 0700)
	j := IsolationJournal{Version: 1, Items: []IsolationRecord{{ID: "recovered", Original: p, Quarantine: dest, State: "preparing"}}}
	if e := s.Save(j); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(p, dest); e != nil {
		t.Fatal(e)
	}
	j, e := s.LoadReconciled()
	if e != nil || j.Items[0].State != "isolated" {
		t.Fatalf("reconcile %+v %v", j, e)
	}
	_, e = s.RestoreAll()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(p); e != nil {
		t.Fatal("failed restore", e)
	}
}
func TestCorruptJournalFailsClosed(t *testing.T) {
	s, p := testStore(t)
	os.MkdirAll(s.DataDir, 0700)
	os.Mkdir(p, 0700)
	os.WriteFile(filepath.Join(s.DataDir, "isolation.json"), []byte("{{bad"), 0600)
	if _, e := s.Quarantine(p); e == nil {
		t.Fatal("allowed operation over corrupt journal")
	}
	if _, e := os.Stat(p); e != nil {
		t.Fatal("source lost after corrupted journal")
	}
}

func TestMaliciousJournalPathNotRestored(t *testing.T) {
	s, p := testStore(t)
	os.MkdirAll(filepath.Join(s.DataDir, "Quarantine"), 0700)
	outside := filepath.Join(t.TempDir(), "not_quarantine")
	os.Mkdir(outside, 0700)
	os.WriteFile(filepath.Join(outside, "important.txt"), []byte("keep"), 0600)
	j := IsolationJournal{Version: 1, Items: []IsolationRecord{{ID: "legit", Original: p, Quarantine: outside, State: "isolated"}}}
	if e := s.Save(j); e != nil {
		t.Fatal(e)
	}
	msgs, e := s.RestoreAll()
	if e == nil {
		t.Fatalf("forged journal must fail closed: %v", msgs)
	}
	if _, e := os.Stat(filepath.Join(outside, "important.txt")); e != nil {
		t.Fatal("modified unrelated directory", e)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatalf("created target from untrusted journal %v", e)
	}
}

func TestSharedProgramDataRefusedButPreviousRecordsCanBeRestored(t *testing.T) {
	s, _ := testStore(t)
	pRoot := filepath.Join(t.TempDir(), "ProgramData")
	s.Roots["ProgramData"] = pRoot
	if err := os.MkdirAll(pRoot, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(pRoot, "360")
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	if _, e := s.Quarantine(p); e == nil {
		t.Fatal("allowed new shared ProgramData quarantine")
	}
	if _, e := os.Stat(p); e != nil {
		t.Fatal("shared data was moved", e)
	}
}
func TestJournalRejectsDuplicateIDAndBadState(t *testing.T) {
	s, p := testStore(t)
	if e := os.MkdirAll(s.DataDir, 0700); e != nil {
		t.Fatal(e)
	}
	dest := filepath.Join(s.DataDir, "Quarantine", "unique")
	cases := []IsolationJournal{
		{Version: 1, Items: []IsolationRecord{{ID: "unique", Original: p, Quarantine: dest, State: "mystery"}}},
		{Version: 1, Items: []IsolationRecord{{ID: "unique", Original: p, Quarantine: dest, State: "isolated"}, {ID: "unique", Original: p, Quarantine: dest, State: "isolated"}}},
		{Version: 1, Items: []IsolationRecord{{ID: "unique", Original: filepath.Join(t.TempDir(), "another"), Quarantine: dest, State: "isolated"}}},
	}
	for i, j := range cases {
		if e := s.Save(j); e != nil {
			t.Fatal(e)
		}
		if _, e := s.LoadReconciled(); e == nil {
			t.Errorf("accepted forged journal #%d", i)
		}
	}
}
func TestRestoreRejectsSymlinkedParent(t *testing.T) {
	s, p := testStore(t)
	s.DataDir = filepath.Join(t.TempDir(), "trusted-state")
	if e := os.MkdirAll(p, 0700); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(p, "kept.txt"), []byte("important"), 0600)
	r, e := s.Quarantine(p)
	if e != nil {
		t.Fatal(e)
	}
	parent := filepath.Dir(p)
	target := filepath.Join(t.TempDir(), "alternative")
	if e := os.MkdirAll(target, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(parent, parent+"-old"); e != nil {
		t.Skipf("cannot simulate junction parent: %v", e)
	}
	if e := os.Symlink(target, parent); e != nil {
		t.Skipf("cannot create symlink on this host: %v", e)
	}
	_, e = s.RestoreAll()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(r.Quarantine); e != nil {
		t.Fatal("lost quarantined data", e)
	}
	if _, e := os.Stat(filepath.Join(target, "360se6")); !os.IsNotExist(e) {
		t.Fatalf("restored via symlink: %v", e)
	}
}

// An isolation journal is safety-critical: trailing data must not be ignored.
func TestIsolationJournalRejectsTrailingJSON(t *testing.T) {
	s, _ := testStore(t)
	if err := os.MkdirAll(s.DataDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`{"version":1,"items":[]} {"version":1}`, `{"version":1,"items":[]} nonsense`} {
		if err := os.WriteFile(filepath.Join(s.DataDir, "isolation.json"), []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(); err == nil {
			t.Fatalf("accepted trailing bytes: %q", invalid)
		}
	}
}
