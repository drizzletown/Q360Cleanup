package safecore

import (
	"testing"
	"time"
)

func TestWorkflowTransitions(t *testing.T) {
	cases := []struct {
		from, to string
		allowed  bool
	}{
		{"pending", "running", true},
		{"pending", "verified", false},
		{"running", "verified", true},
		{"running", "reboot_pending", true},
		{"running", "failed", true},
		{"running", "blocked", true},
		{"verified", "running", false},
		{"failed", "verified", false},
		{"blocked", "verified", false},
		{"unknown", "running", false},
	}
	for _, tc := range cases {
		if got := ValidTransition(tc.from, tc.to); got != tc.allowed {
			t.Errorf("%s->%s: %v", tc.from, tc.to, got)
		}
	}
	for _, s := range []string{"pending", "running", "verified", "reboot_pending", "failed", "blocked"} {
		if !ValidTargetState(s) {
			t.Fatalf("expected valid state: %q", s)
		}
	}
	for _, s := range []string{"", "completed", "success", "restored", "UNKNOWN"} {
		if ValidTargetState(s) {
			t.Fatalf("accepted invalid state: %q", s)
		}
	}
}
func TestRebootEvidence(t *testing.T) {
	start := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	priorBoot := start.Add(-2 * time.Hour)
	tests := []struct {
		name          string
		before, after time.Time
		yes           bool
	}{
		{"actually rebooted", priorBoot, start.Add(20 * time.Second), true},
		{"same boot drifting seconds", priorBoot, priorBoot.Add(5 * time.Second), false},
		{"old boot thirty-one seconds drift but earlier than session", priorBoot, priorBoot.Add(45 * time.Second), false},
		{"new boot same minute as start", priorBoot, start.Add(5 * time.Second), true},
		{"missing boot", time.Time{}, start.Add(time.Hour), false},
		{"backwards", priorBoot, start.Add(-4 * time.Hour), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RebootAfter(start, tc.before, tc.after); got != tc.yes {
				t.Errorf("reboot=%v want=%v", got, tc.yes)
			}
		})
	}
}
func TestVerdictRejectsIncompleteWorkflows(t *testing.T) {
	baseline := Evidence{SessionExists: true, RebootObserved: true}
	if got := Assess(baseline).Level; got != "范围内通过" {
		t.Fatal(got)
	}
	baseline.WorkflowFailed = true
	if got := Assess(baseline).Level; got != "卸载失败" {
		t.Fatal(got)
	}
	baseline.WorkflowFailed = false
	baseline.WorkflowIncomplete = true
	if got := Assess(baseline).Level; got != "卸载流程未完成" {
		t.Fatal(got)
	}
	baseline.ScanError = true
	if got := Assess(baseline).Level; got != "无法判定" {
		t.Fatal(got)
	}
}
