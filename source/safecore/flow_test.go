package safecore

import "testing"

func TestBatchWorkflowGates(t *testing.T) {
	tests := []struct {
		name          string
		step          UninstallStep
		continueBatch bool
	}{
		{"finished", UninstallStep{ExitAccepted: true, RegisteredKnown: true}, true},
		{"exit failure", UninstallStep{RegisteredKnown: true}, false},
		{"unknown registry", UninstallStep{ExitAccepted: true}, false},
		{"still installed", UninstallStep{ExitAccepted: true, RegisteredKnown: true, StillRegistered: true}, false},
		{"reboot pending", UninstallStep{ExitAccepted: true, RegisteredKnown: true, RebootRequired: true}, false},
		{"reboot plus registered", UninstallStep{ExitAccepted: true, RegisteredKnown: true, StillRegistered: true, RebootRequired: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := DecideBatchStep(tc.step)
			if d.MayStartAnother != tc.continueBatch || d.Reason == "" {
				t.Fatalf("unexpected decision: %+v", d)
			}
		})
	}
}
